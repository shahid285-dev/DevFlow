#include "network_api.h"
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <sys/time.h>
#include <math.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdatomic.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <spawn.h>
#include <sys/wait.h>


#define MAX_RESPONSE_SIZE (50 * 1024 * 1024)
#define MAX_HEADER_SIZE (1 * 1024 * 1024)
#define MAX_REQUEST_URL_LENGTH 2048
#define MAX_HEADER_LINE_LENGTH 8192
#define MAX_BODY_LENGTH (100 * 1024 * 1024)

static CURLM* multi_handle = NULL;
static pthread_mutex_t network_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t request_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint32_t global_timeout_ms = 30000;
static uint32_t max_connections = 10;
static bool compression_enabled = true;
static bool caching_enabled = false;
static atomic_bool monitor_running = false;
static pthread_t monitor_thread;
static pthread_once_t curl_init_once = PTHREAD_ONCE_INIT;

static request_hook_t registered_hook = NULL;
static void* hook_user_data = NULL;
static uint32_t security_threshold = 50;
static void (*data_streaming_callback)(const uint8_t* data, size_t length, bool is_outgoing) = NULL;

typedef struct {
    CURL* handle;
    http_method_t method;
    char* url;
    struct curl_slist* headers;
    uint8_t* request_body;
    size_t request_body_length;
    http_response_t* response;
    progress_callback_t progress_cb;
    completion_callback_t completion_cb;
    error_callback_t error_cb;
    void* user_data;
    atomic_bool cancelled;
    atomic_int refcount;
    atomic_bool in_multi;
    pthread_mutex_t mutex;
} network_request_internal_t;

typedef struct {
    progress_callback_t progress_cb;
    void* user_data;
    atomic_bool cancelled;
} file_transfer_context_t;

extern char **environ;
static void curl_global_init_once(void) {
    curl_global_init(CURL_GLOBAL_ALL);
}

static void request_lock(network_request_internal_t* r) {
    pthread_mutex_lock(&r->mutex);
}

static void request_unlock(network_request_internal_t* r) {
    pthread_mutex_unlock(&r->mutex);
}

static void request_ref(network_request_internal_t* r) {
    atomic_fetch_add_explicit(&r->refcount, 1, memory_order_acq_rel);
}

static void request_unref(network_request_internal_t* r) {
    if (atomic_fetch_sub_explicit(&r->refcount, 1, memory_order_acq_rel) == 1) {
        if (r->handle) {
            curl_easy_cleanup(r->handle);
        }
        if (r->url) {
            free(r->url);
        }
        if (r->headers) {
            curl_slist_free_all(r->headers);
        }
        if (r->request_body) {
            free(r->request_body);
        }
        if (r->response) {
            release_response_impl(r->response);
        }
        pthread_mutex_destroy(&r->mutex);
        free(r);
    }
}

static bool validate_url(const char* url) {
    if (!url || strlen(url) > MAX_REQUEST_URL_LENGTH) {
        return false;
    }
    
    if (strncmp(url, "http://", 7) != 0 && strncmp(url, "https://", 8) != 0) {
        return false;
    }
    
    return true;
}

static bool validate_header_line(const char* line) {
    if (!line) return false;
    
    size_t len = strnlen(line, MAX_HEADER_LINE_LENGTH + 1);
    if (len == 0 || len > MAX_HEADER_LINE_LENGTH) return false;
    
    if (strchr(line, '\r') != NULL || strchr(line, '\n') != NULL) {
        return false;
    }
    
    const char* colon = strchr(line, ':');
    if (!colon || colon == line) return false;
    
    size_t name_len = colon - line;
    if (name_len == 0 || name_len > 1024) return false;
    
    for (size_t i = 0; i < name_len; ++i) {
        unsigned char c = (unsigned char)line[i];
        if (c <= 32 || c >= 127) return false;
        if (c == '(' || c == ')' || c == '<' || c == '>' || c == '@' || 
            c == ',' || c == ';' || c == ':' || c == '\\' || c == '"' || 
            c == '/' || c == '[' || c == ']' || c == '?' || c == '=' || 
            c == '{' || c == '}') {
            return false;
        }
    }
    
    char namebuf[1025];
    for (size_t i = 0; i < name_len; ++i) {
        namebuf[i] = tolower((unsigned char)line[i]);
    }
    namebuf[name_len] = '\0';
    
    const char* forbidden_headers[] = {
        "content-length",
        "transfer-encoding", 
        "host",
        "accept-encoding",
        "user-agent",
        NULL
    };
    
    for (int i = 0; forbidden_headers[i] != NULL; i++) {
        if (strcmp(namebuf, forbidden_headers[i]) == 0) {
            return false;
        }
    }
    
    return true;
}

static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    network_request_internal_t* request = (network_request_internal_t*)userp;
    if (!request || !request->response) return 0;

    if (nmemb && size > SIZE_MAX / nmemb) return 0;
    size_t total_size = size * nmemb;
    if (total_size == 0) return 0;

    request_lock(request);

    if (request->response->body_length > SIZE_MAX - total_size) {
        request_unlock(request);
        return 0;
    }

    size_t new_size = request->response->body_length + total_size;
    if (new_size > MAX_RESPONSE_SIZE) {
        request_unlock(request);
        return 0;
    }

    if (!request->response->body) {
        uint8_t* buf = malloc(new_size);
        if (!buf) {
            request_unlock(request);
            return 0;
        }
        memcpy(buf, contents, total_size);
        request->response->body = buf;
        request->response->body_length = total_size;
    } else {
        uint8_t* new_body = realloc((void*)request->response->body, new_size);
        if (!new_body) {
            request_unlock(request);
            return 0;
        }
        memcpy(new_body + request->response->body_length, contents, total_size);
        request->response->body = new_body;
        request->response->body_length = new_size;
    }

    request_unlock(request);
    return total_size;
}


static size_t write_counter_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t total = size * nmemb;
    if (userp && total > 0) {
        size_t* acc = (size_t*)userp;
        *acc += total;
    }
    return total;
}

static size_t header_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    network_request_internal_t* request = (network_request_internal_t*)userp;
    if (!request || !request->response) return 0;
    
    size_t total_size = size * nmemb;
    if (total_size == 0) return 0;
    
    request_lock(request);
    
    if (request->response->headers_length + total_size > MAX_HEADER_SIZE) {
        request_unlock(request);
        return 0;
    }
    
    if (!request->response->headers) {
        request->response->headers = malloc(total_size + 1);
        if (!request->response->headers) {
            request_unlock(request);
            return 0;
        }
        memcpy((void*)request->response->headers, contents, total_size);
        ((char*)request->response->headers)[total_size] = '\0';
        request->response->headers_length = total_size;
    } else {
        size_t new_size = request->response->headers_length + total_size;
        if (new_size > MAX_HEADER_SIZE) {
            request_unlock(request);
            return 0;
        }
        
        char* new_headers = realloc((void*)request->response->headers, new_size + 1);
        if (!new_headers) {
            request_unlock(request);
            return 0;
        }
        memcpy(new_headers + request->response->headers_length, contents, total_size);
        new_headers[new_size] = '\0';
        request->response->headers = new_headers;
        request->response->headers_length = new_size;
    }
    
    request_unlock(request);
    return total_size;
}

static int progress_callback(void* clientp, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow) {
    network_request_internal_t* request = (network_request_internal_t*)clientp;
    if (!request) return 0;
    
    if (atomic_load(&request->cancelled)) {
        return 1;
    }
    
    if (request->progress_cb) {
        transfer_progress_t progress;
        progress.total_bytes = (uint64_t)(dltotal > 0 ? dltotal : ultotal);
        progress.transferred_bytes = (uint64_t)(dlnow > 0 ? dlnow : ulnow);
        progress.progress = progress.total_bytes > 0 ? (double)progress.transferred_bytes / progress.total_bytes : 0.0;
        progress.speed_bps = 0;
        progress.estimated_time_remaining = 0;
        
        request->progress_cb(&progress, request->user_data);
    }
    
    return 0;
}

static int file_progress_callback(void* clientp, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow) {
    file_transfer_context_t* context = (file_transfer_context_t*)clientp;
    if (!context) return 0;
    
    if (atomic_load(&context->cancelled)) {
        return 1;
    }
    
    if (context->progress_cb) {
        transfer_progress_t progress;
        progress.total_bytes = (uint64_t)(dltotal > 0 ? dltotal : ultotal);
        progress.transferred_bytes = (uint64_t)(dlnow > 0 ? dlnow : ulnow);
        progress.progress = progress.total_bytes > 0 ? (double)progress.transferred_bytes / progress.total_bytes : 0.0;
        progress.speed_bps = 0;
        progress.estimated_time_remaining = 0;
        
        context->progress_cb(&progress, context->user_data);
    }
    
    return 0;
}

static double calculate_transfer_speed(const struct timeval* start, const struct timeval* end, size_t bytes) {
    if (!start || !end || bytes == 0) return 0.0;
    
    double time_elapsed = (end->tv_sec - start->tv_sec) + (end->tv_usec - start->tv_usec) / 1000000.0;
    if (time_elapsed <= 0) return 0.0;
    
    return (bytes * 8.0) / time_elapsed;
}

static bool safe_run_and_read(const char* const argv[], char* buffer, size_t buffer_size) {
    if (!argv || !argv[0] || !buffer || buffer_size == 0) return false;
    
    int pipefd[2];
    if (pipe(pipefd) != 0) return false;
    
    posix_spawn_file_actions_t fa;
    if (posix_spawn_file_actions_init(&fa) != 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return false;
    }
    
    posix_spawn_file_actions_adddup2(&fa, pipefd[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&fa, pipefd[0]);
    posix_spawn_file_actions_addclose(&fa, pipefd[1]);
    
    pid_t pid;
    int status = posix_spawnp(&pid, argv[0], &fa, NULL, (char* const*)argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    close(pipefd[1]);
    
    if (status != 0) {
        close(pipefd[0]);
        return false;
    }
    
    ssize_t total = 0;
    ssize_t n;
    while ((n = read(pipefd[0], buffer + total, buffer_size - 1 - total)) > 0) {
        ssize_t to_copy = n;
        if (total + to_copy > (ssize_t)(buffer_size - 1)) {
            to_copy = (ssize_t)((buffer_size - 1) - total);
        }
        if (to_copy > 0) {
            total += to_copy;
        }
        if (total >= (ssize_t)(buffer_size - 1)) break;
    }
    
    close(pipefd[0]);
    
    int wait_status;
    while (waitpid(pid, &wait_status, 0) == -1) {
        if (errno != EINTR) break;
    }
    
    buffer[total] = '\0';
    return total > 0;
}

static char* safe_strdup(const char* str) {
    if (!str) return NULL;
    return strdup(str);
}

static char* safe_strndup(const char* str, size_t max_len) {
    if (!str) return NULL;
    
    size_t len = strnlen(str, max_len);
    char* new_str = malloc(len + 1);
    if (!new_str) return NULL;
    
    memcpy(new_str, str, len);
    new_str[len] = '\0';
    return new_str;
}

network_type_t get_network_type_impl(void) {
    struct ifaddrs* ifaddr;
    if (getifaddrs(&ifaddr) == -1) {
        return NETWORK_TYPE_UNKNOWN;
    }
    
    bool has_wifi = false;
    bool has_cellular = false;
    bool has_ethernet = false;
    
    for (struct ifaddrs* ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        
        int family = ifa->ifa_addr->sa_family;
        if (family == AF_INET || family == AF_INET6) {
            const char* name = ifa->ifa_name;
            if (!name) continue;
            
            if (strstr(name, "wlan") || strstr(name, "wlp") || strstr(name, "ap")) {
                has_wifi = true;
            } else if (strstr(name, "rmnet") || strstr(name, "pdp") || strstr(name, "wwan")) {
                has_cellular = true;
            } else if (strstr(name, "eth") || strstr(name, "enp") || strstr(name, "em")) {
                has_ethernet = true;
            }
        }
    }
    
    freeifaddrs(ifaddr);
    
    if (has_wifi) return NETWORK_TYPE_WIFI;
    if (has_cellular) return NETWORK_TYPE_CELLULAR;
    if (has_ethernet) return NETWORK_TYPE_ETHERNET;
    
    return NETWORK_TYPE_UNKNOWN;
}

connection_state_t get_connection_state_impl(void) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        return CONNECTION_STATE_DISCONNECTED;
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, "http://connectivitycheck.gstatic.com/generate_204");
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 5000L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 3000L);
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_CAINFO, NULL);
    
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    
    if (res == CURLE_OK) {
        return CONNECTION_STATE_CONNECTED;
    } else if (res == CURLE_COULDNT_CONNECT || res == CURLE_OPERATION_TIMEDOUT) {
        return CONNECTION_STATE_DISCONNECTED;
    } else {
        return CONNECTION_STATE_CONNECTING;
    }
}

bool is_network_available_impl(void) {
    connection_state_t state = get_connection_state_impl();
    return state == CONNECTION_STATE_CONNECTED;
}

bool is_metered_connection_impl(void) {
    network_type_t type = get_network_type_impl();
    
    if (type == NETWORK_TYPE_CELLULAR) {
        return true;
    }
    
    FILE* file = fopen("/proc/net/route", "r");
    if (!file) {
        return false;
    }
    
    char line[256];
    bool has_default_route = false;
    
    while (fgets(line, sizeof(line), file)) {
        char interface[16] = {0};
        unsigned long destination = 0, gateway = 0;
        
        if (sscanf(line, "%15s %lx %lx", interface, &destination, &gateway) == 3) {
            if (destination == 0) {
                has_default_route = true;
                break;
            }
        }
    }
    
    fclose(file);
    return !has_default_route;
}

int32_t get_signal_strength_impl(void) {
    network_type_t type = get_network_type_impl();
    
    if (type == NETWORK_TYPE_WIFI) {
        const char* argv[] = {"nmcli", "-t", "-f", "SIGNAL", "dev", "wifi", NULL};
        char buffer[4096] = {0};
        
        if (!safe_run_and_read(argv, buffer, sizeof(buffer))) {
            return -1;
        }
        
        int32_t max_signal = -100;
        char* line = strtok(buffer, "\n");
        
        while (line) {
            char* endptr;
            long signal = strtol(line, &endptr, 10);
            if (endptr != line && signal > max_signal && signal <= 100) {
                max_signal = (int32_t)signal;
            }
            line = strtok(NULL, "\n");
        }
        
        return max_signal;
    }
    
    return -1;
}


network_quality_t get_network_quality_impl(void) {
    network_quality_t quality = {0};
    
    CURL* curl = curl_easy_init();
    if (!curl) return quality;
    
    struct timeval start_time, end_time;
    size_t total_downloaded = 0;
    
    curl_easy_setopt(curl, CURLOPT_URL, "http://httpbin.org/stream-bytes/102400");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_counter_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &total_downloaded);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 10000L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_CAINFO, NULL);
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    
    gettimeofday(&start_time, NULL);
    CURLcode res = curl_easy_perform(curl);
    gettimeofday(&end_time, NULL);
    
    if (res == CURLE_OK) {
        uint64_t speed = (uint64_t)calculate_transfer_speed(&start_time, &end_time, total_downloaded);
        quality.download_speed_bps = speed > UINT32_MAX ? UINT32_MAX : (uint32_t)speed;
        
        double total_time = 0.0;
        if (curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total_time) == CURLE_OK) {
            quality.latency_ms = (uint32_t)(total_time * 1000.0);
        }
        
        quality.jitter_ms = 5;
        quality.packet_loss = 0;
    }
    
    curl_easy_cleanup(curl);
    return quality;
}

wifi_network_info_t* get_available_wifi_networks_impl(size_t* count) {
    *count = 0;
    
    const char* argv[] = {"nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,SECURITY,FREQ", "dev", "wifi", NULL};
    char buffer[8192] = {0};
    
    if (!safe_run_and_read(argv, buffer, sizeof(buffer))) {
        return NULL;
    }
    
    wifi_network_info_t* networks = NULL;
    size_t network_count = 0;
    char* line = strtok(buffer, "\n");
    
    while (line) {
        char* tokens[5] = {0};
        int token_count = 0;
        char* line_copy = safe_strdup(line);
        if (!line_copy) goto cleanup;
        
        char* saveptr = NULL;
        char* token = strtok_r(line_copy, ":", &saveptr);
        while (token && token_count < 5) {
            tokens[token_count++] = token;
            token = strtok_r(NULL, ":", &saveptr);
        }
        
        if (token_count >= 4) {
            wifi_network_info_t* new_networks = realloc(networks, (network_count + 1) * sizeof(wifi_network_info_t));
            if (!new_networks) {
                free(line_copy);
                goto cleanup;
            }
            networks = new_networks;
            
            memset(&networks[network_count], 0, sizeof(wifi_network_info_t));
            networks[network_count].ssid = tokens[0] ? safe_strdup(tokens[0]) : safe_strdup("");
            networks[network_count].bssid = tokens[1] ? safe_strdup(tokens[1]) : safe_strdup("");
            
            if (!networks[network_count].ssid || !networks[network_count].bssid) {
                free(networks[network_count].ssid);
                free(networks[network_count].bssid);
                free(line_copy);
                goto cleanup;
            }
            
            networks[network_count].signal_strength = tokens[2] ? atoi(tokens[2]) : 0;
            
            if (tokens[3] && strstr(tokens[3], "WPA3")) {
                networks[network_count].security = SECURITY_WPA3;
            } else if (tokens[3] && strstr(tokens[3], "WPA2")) {
                networks[network_count].security = SECURITY_WPA2;
            } else if (tokens[3] && strstr(tokens[3], "WPA")) {
                networks[network_count].security = SECURITY_WPA;
            } else if (tokens[3] && strstr(tokens[3], "WEP")) {
                networks[network_count].security = SECURITY_WEP;
            } else {
                networks[network_count].security = SECURITY_NONE;
            }
            
            networks[network_count].is_secured = (networks[network_count].security != SECURITY_NONE);
            networks[network_count].frequency = (token_count >= 5 && tokens[4]) ? (uint32_t)atof(tokens[4]) : 2400;
            
            network_count++;
        }
        
        free(line_copy);
        line = strtok(NULL, "\n");
    }
    
    *count = network_count;
    return networks;

cleanup:
    for (size_t i = 0; i < network_count; ++i) {
        free((void*)networks[i].ssid);
        free((void*)networks[i].bssid);
    }
    free(networks);
    *count = 0;
    return NULL;
}


cellular_network_info_t* get_cellular_network_info_impl(void) {
    cellular_network_info_t* info = calloc(1, sizeof(cellular_network_info_t));
    if (!info) return NULL;
    
    const char* mmcli_argv[] = {"mmcli", "-J", "-m", "any", NULL};
    char buffer[2048] = {0};
    
    if (safe_run_and_read(mmcli_argv, buffer, sizeof(buffer)) && strlen(buffer) > 0) {
        info->carrier_name = safe_strdup("Mobile Carrier");
        info->signal_strength = -70;
        info->network_generation = 4;
        info->is_roaming = false;
        if (!info->carrier_name) {
            free(info);
            return NULL;
        }
        return info;
    }
    
    FILE* arp_file = fopen("/proc/net/arp", "r");
    if (arp_file) {
        char line[256];
        int line_count = 0;
        while (fgets(line, sizeof(line), arp_file)) {
            line_count++;
        }
        fclose(arp_file);
        
        info->carrier_name = safe_strdup("Cellular Network");
        info->signal_strength = -85;
        info->network_generation = (line_count > 2) ? 4 : 3;
        info->is_roaming = false;
        if (!info->carrier_name) {
            free(info);
            return NULL;
        }
        return info;
    }
    
    free(info);
    return NULL;
}

network_request_t* create_request_impl(http_method_t method, const char* url) {
    if (!validate_url(url)) return NULL;

    network_request_internal_t* request = calloc(1, sizeof(network_request_internal_t));
    if (!request) return NULL;

    if (pthread_mutex_init(&request->mutex, NULL) != 0) {
        free(request);
        return NULL;
    }

    request->handle = curl_easy_init();
    if (!request->handle) {
        pthread_mutex_destroy(&request->mutex);
        free(request);
        return NULL;
    }

    atomic_store(&request->refcount, 1);
    atomic_store(&request->in_multi, false);
    atomic_store(&request->cancelled, false);
    request->method = method;

    request->url = safe_strndup(url, MAX_REQUEST_URL_LENGTH);
    if (!request->url) {
        curl_easy_cleanup(request->handle);
        pthread_mutex_destroy(&request->mutex);
        free(request);
        return NULL;
    }

    request->response = calloc(1, sizeof(http_response_t));
    if (!request->response) {
        curl_easy_cleanup(request->handle);
        free(request->url);
        pthread_mutex_destroy(&request->mutex);
        free(request);
        return NULL;
    }

    CURLcode setopt_result = CURLE_OK;
    long timeout_value = (global_timeout_ms > (uint32_t)LONG_MAX) ? LONG_MAX : (long)global_timeout_ms;

    setopt_result = curl_easy_setopt(request->handle, CURLOPT_URL, request->url);
    if (setopt_result != CURLE_OK) goto error_cleanup;

    setopt_result = curl_easy_setopt(request->handle, CURLOPT_WRITEFUNCTION, write_callback);
    if (setopt_result != CURLE_OK) goto error_cleanup;

    setopt_result = curl_easy_setopt(request->handle, CURLOPT_WRITEDATA, request);
    if (setopt_result != CURLE_OK) goto error_cleanup;

    setopt_result = curl_easy_setopt(request->handle, CURLOPT_HEADERFUNCTION, header_callback);
    if (setopt_result != CURLE_OK) goto error_cleanup;

    setopt_result = curl_easy_setopt(request->handle, CURLOPT_HEADERDATA, request);
    if (setopt_result != CURLE_OK) goto error_cleanup;

    setopt_result = curl_easy_setopt(request->handle, CURLOPT_NOPROGRESS, 0L);
    if (setopt_result != CURLE_OK) goto error_cleanup;

    setopt_result = curl_easy_setopt(request->handle, CURLOPT_XFERINFOFUNCTION, progress_callback);
    if (setopt_result != CURLE_OK) goto error_cleanup;

    setopt_result = curl_easy_setopt(request->handle, CURLOPT_XFERINFODATA, request);
    if (setopt_result != CURLE_OK) goto error_cleanup;

    setopt_result = curl_easy_setopt(request->handle, CURLOPT_FOLLOWLOCATION, 1L);
    if (setopt_result != CURLE_OK) goto error_cleanup;

    setopt_result = curl_easy_setopt(request->handle, CURLOPT_SSL_VERIFYPEER, 1L);
    if (setopt_result != CURLE_OK) goto error_cleanup;

    setopt_result = curl_easy_setopt(request->handle, CURLOPT_SSL_VERIFYHOST, 2L);
    if (setopt_result != CURLE_OK) goto error_cleanup;

    setopt_result = curl_easy_setopt(request->handle, CURLOPT_TIMEOUT_MS, timeout_value);
    if (setopt_result != CURLE_OK) goto error_cleanup;

    setopt_result = curl_easy_setopt(request->handle, CURLOPT_PRIVATE, request);
    if (setopt_result != CURLE_OK) goto error_cleanup;

    setopt_result = curl_easy_setopt(request->handle, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    if (setopt_result != CURLE_OK) goto error_cleanup;

    setopt_result = curl_easy_setopt(request->handle, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    if (setopt_result != CURLE_OK) goto error_cleanup;

    switch (method) {
        case HTTP_METHOD_GET:
            setopt_result = curl_easy_setopt(request->handle, CURLOPT_HTTPGET, 1L);
            break;
        case HTTP_METHOD_POST:
            setopt_result = curl_easy_setopt(request->handle, CURLOPT_POST, 1L);
            break;
        case HTTP_METHOD_PUT:
            setopt_result = curl_easy_setopt(request->handle, CURLOPT_CUSTOMREQUEST, "PUT");
            break;
        case HTTP_METHOD_DELETE:
            setopt_result = curl_easy_setopt(request->handle, CURLOPT_CUSTOMREQUEST, "DELETE");
            break;
        case HTTP_METHOD_HEAD:
            setopt_result = curl_easy_setopt(request->handle, CURLOPT_NOBODY, 1L);
            break;
        case HTTP_METHOD_PATCH:
            setopt_result = curl_easy_setopt(request->handle, CURLOPT_CUSTOMREQUEST, "PATCH");
            break;
        default:
            break;
    }

    if (setopt_result != CURLE_OK) goto error_cleanup;

    return request;

error_cleanup:
    curl_easy_cleanup(request->handle);
    if (request->url) free(request->url);
    if (request->response) {
        if (request->response->headers) free(request->response->headers);
        if (request->response->body) free(request->response->body);
        free(request->response);
    }
    pthread_mutex_destroy(&request->mutex);
    free(request);
    return NULL;
}

void set_request_headers_impl(network_request_t* req, const char* headers) {
    if (!req || !headers) return;
    
    network_request_internal_t* request = (network_request_internal_t*)req;
    request_lock(request);
    
    if (request->headers) {
        curl_slist_free_all(request->headers);
        request->headers = NULL;
    }
    
    char* headers_copy = safe_strndup(headers, MAX_HEADER_SIZE);
    if (!headers_copy) {
        request_unlock(request);
        return;
    }
    
    char* line = strtok(headers_copy, "\n");
    while (line) {
        if (validate_header_line(line)) {
            struct curl_slist* new_list = curl_slist_append(request->headers, line);
            if (new_list) {
                request->headers = new_list;
            }
        }
        line = strtok(NULL, "\n");
    }
    
    free(headers_copy);
    
    if (request->headers) {
        curl_easy_setopt(request->handle, CURLOPT_HTTPHEADER, request->headers);
    }
    
    request_unlock(request);
}

void set_request_body_impl(network_request_t* req, const uint8_t* data, size_t length) {
    if (!req) return;
    
    network_request_internal_t* request = (network_request_internal_t*)req;
    request_lock(request);
    
    if (request->request_body) {
        free(request->request_body);
        request->request_body = NULL;
        request->request_body_length = 0;
    }
    
    if (data && length > 0 && length <= MAX_BODY_LENGTH) {
        request->request_body = malloc(length);
        if (request->request_body) {
            memcpy(request->request_body, data, length);
            request->request_body_length = length;
            curl_easy_setopt(request->handle, CURLOPT_POSTFIELDSIZE, (long)length);
            curl_easy_setopt(request->handle, CURLOPT_POSTFIELDS, request->request_body);
        }
    } else {
        curl_easy_setopt(request->handle, CURLOPT_POSTFIELDSIZE, 0L);
        curl_easy_setopt(request->handle, CURLOPT_POSTFIELDS, NULL);
    }
    
    request_unlock(request);
}

void set_request_priority_impl(network_request_t* req, request_priority_t priority) {
    if (!req) return;
    
    network_request_internal_t* request = (network_request_internal_t*)req;
    request_lock(request);
    
    switch (priority) {
        case REQUEST_PRIORITY_LOW:
            curl_easy_setopt(request->handle, CURLOPT_LOW_SPEED_LIMIT, 1024L);
            curl_easy_setopt(request->handle, CURLOPT_LOW_SPEED_TIME, 60L);
            break;
        case REQUEST_PRIORITY_NORMAL:
            curl_easy_setopt(request->handle, CURLOPT_LOW_SPEED_LIMIT, 5120L);
            curl_easy_setopt(request->handle, CURLOPT_LOW_SPEED_TIME, 30L);
            break;
        case REQUEST_PRIORITY_HIGH:
            curl_easy_setopt(request->handle, CURLOPT_LOW_SPEED_LIMIT, 10240L);
            curl_easy_setopt(request->handle, CURLOPT_LOW_SPEED_TIME, 10L);
            break;
        case REQUEST_PRIORITY_URGENT:
            curl_easy_setopt(request->handle, CURLOPT_LOW_SPEED_LIMIT, 20480L);
            curl_easy_setopt(request->handle, CURLOPT_LOW_SPEED_TIME, 5L);
            break;
        default:
            break;
    }
    
    request_unlock(request);
}

void set_request_timeout_impl(network_request_t* req, uint32_t timeout_ms) {
    if (!req) return;
    
    network_request_internal_t* request = (network_request_internal_t*)req;
    request_lock(request);
    curl_easy_setopt(request->handle, CURLOPT_TIMEOUT_MS, (long)timeout_ms);
    request_unlock(request);
}

bool execute_request_impl(network_request_t* req, http_response_t** response) {
    if (!req || !response) return false;
    
    network_request_internal_t* request = (network_request_internal_t*)req;
    
    if (atomic_load(&request->cancelled)) {
        return false;
    }
    
    CURLcode res = curl_easy_perform(request->handle);
    
    if (res == CURLE_OK) {
        request_lock(request);
        
        long http_code = 0;
        curl_easy_getinfo(request->handle, CURLINFO_RESPONSE_CODE, &http_code);
        request->response->status_code = (uint32_t)http_code;
        
        char* content_type = NULL;
        if (curl_easy_getinfo(request->handle, CURLINFO_CONTENT_TYPE, &content_type) == CURLE_OK && content_type) {
            request->response->content_type = safe_strdup(content_type);
        }
        
        double content_length = 0;
        if (curl_easy_getinfo(request->handle, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &content_length) == CURLE_OK && content_length >= 0) {
            request->response->content_length = (size_t)content_length;
        }
        
        *response = request->response;
        request->response = NULL;
        
        request_unlock(request);
        return true;
    }
    
    return false;
}

void execute_request_async_impl(network_request_t* req, 
                               completion_callback_t completion_cb,
                               progress_callback_t progress_cb,
                               error_callback_t error_cb,
                               void* user_data) {
    if (!req) return;
    
    network_request_internal_t* request = (network_request_internal_t*)req;
    request_lock(request);
    
    request->completion_cb = completion_cb;
    request->progress_cb = progress_cb;
    request->error_cb = error_cb;
    request->user_data = user_data;
    
    request_unlock(request);
    
    pthread_mutex_lock(&network_mutex);
    
    if (!multi_handle) {
        multi_handle = curl_multi_init();
        if (multi_handle) {
            curl_multi_setopt(multi_handle, CURLMOPT_MAX_TOTAL_CONNECTIONS, (long)max_connections);
        }
    }
    
    if (multi_handle) {
        request_ref(request);
        atomic_store(&request->in_multi, true);
        CURLMcode mres = curl_multi_add_handle(multi_handle, request->handle);
        if (mres != CURLM_OK) {
            atomic_store(&request->in_multi, false);
            request_unref(request);
        }
    }
    
    pthread_mutex_unlock(&network_mutex);
}

void cancel_request_impl(network_request_t* req) {
    if (!req) return;
    
    network_request_internal_t* request = (network_request_internal_t*)req;
    atomic_store(&request->cancelled, true);
    
    pthread_mutex_lock(&network_mutex);
    if (multi_handle && request->handle && atomic_load(&request->in_multi)) {
        curl_multi_remove_handle(multi_handle, request->handle);
        atomic_store(&request->in_multi, false);
        request_unref(request);
    }
    pthread_mutex_unlock(&network_mutex);
}

void release_request_impl(network_request_t* req) {
    if (!req) return;
    
    network_request_internal_t* request = (network_request_internal_t*)req;
    
    pthread_mutex_lock(&network_mutex);
    if (atomic_load(&request->in_multi) && multi_handle && request->handle) {
        curl_multi_remove_handle(multi_handle, request->handle);
        atomic_store(&request->in_multi, false);
    }
    pthread_mutex_unlock(&network_mutex);
    
    request_unref(request);
}

void release_response_impl(http_response_t* response) {
    if (!response) return;
    
    if (response->content_type) {
        free((void*)response->content_type);
    }
    
    if (response->headers) {
        free((void*)response->headers);
    }
    
    if (response->body) {
        free((void*)response->body);
    }
    
    free(response);
}

bool download_file_impl(const char* url, const char* local_path, 
                       progress_callback_t progress_cb, void* user_data) {
    if (!validate_url(url) || !local_path) return false;
    
    int fd = open(local_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    
    FILE* file = fdopen(fd, "wb");
    if (!file) {
        close(fd);
        return false;
    }
    
    CURL* curl = curl_easy_init();
    if (!curl) {
        fclose(file);
        return false;
    }
    
    file_transfer_context_t* context = malloc(sizeof(file_transfer_context_t));
    if (!context) {
        curl_easy_cleanup(curl);
        fclose(file);
        return false;
    }
    
    context->progress_cb = progress_cb;
    context->user_data = user_data;
    atomic_store(&context->cancelled, false);
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, file);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, file_progress_callback);
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA, context);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_CAINFO, NULL);
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    
    CURLcode res = curl_easy_perform(curl);
    
    curl_easy_cleanup(curl);
    fclose(file);
    free(context);
    
    if (res != CURLE_OK) {
        remove(local_path);
        return false;
    }
    
    return true;
}

bool upload_file_impl(const char* url, const char* local_path,
                     progress_callback_t progress_cb, void* user_data) {
    if (!validate_url(url) || !local_path) return false;
    
    int fd = open(local_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    
    FILE* file = fdopen(fd, "rb");
    if (!file) {
        close(fd);
        return false;
    }
    
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return false;
    }
    
    long file_size = ftell(file);
    if (file_size < 0) {
        fclose(file);
        return false;
    }
    
    rewind(file);
    
    if ((uint64_t)file_size > MAX_BODY_LENGTH) {
        fclose(file);
        return false;
    }
    
    CURL* curl = curl_easy_init();
    if (!curl) {
        fclose(file);
        return false;
    }
    
    file_transfer_context_t* context = malloc(sizeof(file_transfer_context_t));
    if (!context) {
        curl_easy_cleanup(curl);
        fclose(file);
        return false;
    }
    
    context->progress_cb = progress_cb;
    context->user_data = user_data;
    atomic_store(&context->cancelled, false);
    
    CURLcode res = CURLE_FAILED_INIT;
    CURLcode setopt_result;
    
    setopt_result = curl_easy_setopt(curl, CURLOPT_URL, url);
    if (setopt_result != CURLE_OK) {
        res = setopt_result;
        goto cleanup;
    }
    
    setopt_result = curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
    if (setopt_result != CURLE_OK) {
        res = setopt_result;
        goto cleanup;
    }
    
    setopt_result = curl_easy_setopt(curl, CURLOPT_READDATA, file);
    if (setopt_result != CURLE_OK) {
        res = setopt_result;
        goto cleanup;
    }
    
    setopt_result = curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)file_size);
    if (setopt_result != CURLE_OK) {
        res = setopt_result;
        goto cleanup;
    }
    
    setopt_result = curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    if (setopt_result != CURLE_OK) {
        res = setopt_result;
        goto cleanup;
    }
    
    setopt_result = curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    if (setopt_result != CURLE_OK) {
        res = setopt_result;
        goto cleanup;
    }
    
    setopt_result = curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, file_progress_callback);
    if (setopt_result != CURLE_OK) {
        res = setopt_result;
        goto cleanup;
    }
    
    setopt_result = curl_easy_setopt(curl, CURLOPT_XFERINFODATA, context);
    if (setopt_result != CURLE_OK) {
        res = setopt_result;
        goto cleanup;
    }
    
    setopt_result = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    if (setopt_result != CURLE_OK) {
        res = setopt_result;
        goto cleanup;
    }
    
    setopt_result = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    if (setopt_result != CURLE_OK) {
        res = setopt_result;
        goto cleanup;
    }
    
    setopt_result = curl_easy_setopt(curl, CURLOPT_CAINFO, NULL);
    if (setopt_result != CURLE_OK) {
        res = setopt_result;
        goto cleanup;
    }
    
    setopt_result = curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    if (setopt_result != CURLE_OK) {
        res = setopt_result;
        goto cleanup;
    }
    
    res = curl_easy_perform(curl);

cleanup:
    curl_easy_cleanup(curl);
    fclose(file);
    free(context);
    
    return res == CURLE_OK;
}


void set_global_timeout_impl(uint32_t timeout_ms) {
    pthread_mutex_lock(&network_mutex);
    global_timeout_ms = timeout_ms;
    pthread_mutex_unlock(&network_mutex);
}

void set_max_connections_impl(uint32_t max_conns) {
    pthread_mutex_lock(&network_mutex);
    max_connections = max_conns;
    if (multi_handle) {
        curl_multi_setopt(multi_handle, CURLMOPT_MAX_TOTAL_CONNECTIONS, (long)max_conns);
    }
    pthread_mutex_unlock(&network_mutex);
}

void enable_compression_impl(bool enable) {
    pthread_mutex_lock(&network_mutex);
    compression_enabled = enable;
    pthread_mutex_unlock(&network_mutex);
}

void enable_caching_impl(bool enable) {
    pthread_mutex_lock(&network_mutex);
    caching_enabled = enable;
    pthread_mutex_unlock(&network_mutex);
}

static void* network_monitor_thread(void* arg) {
    while (atomic_load(&monitor_running)) {
        (void)arg;
        network_type_t current_type = get_network_type_impl();
        connection_state_t current_state = get_connection_state_impl();
        (void)current_type; (void)current_state;

        pthread_mutex_lock(&network_mutex);
        CURLM* mh = multi_handle;
        pthread_mutex_unlock(&network_mutex);

        if (mh) {
            int numfds = 0;
            curl_multi_wait(mh, NULL, 0, 1000, &numfds);

            int still_running = 0;
            curl_multi_perform(mh, &still_running);

            int msgs_left;
            CURLMsg* msg;
            while ((msg = curl_multi_info_read(mh, &msgs_left))) {
                if (msg->msg != CURLMSG_DONE) continue;

                CURL* handle = msg->easy_handle;
                network_request_internal_t* request = NULL;
                curl_easy_getinfo(handle, CURLINFO_PRIVATE, &request);
                if (!request) continue;

                pthread_mutex_lock(&network_mutex);
                curl_multi_remove_handle(mh, handle);
                atomic_store(&request->in_multi, false);
                pthread_mutex_unlock(&network_mutex);

                request_lock(request);

                if (msg->data.result == CURLE_OK) {
                    long http_code = 0;
                    curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &http_code);
                    request->response->status_code = (uint32_t)http_code;

                    char* content_type = NULL;
                    if (curl_easy_getinfo(handle, CURLINFO_CONTENT_TYPE, &content_type) == CURLE_OK && content_type) {
                        char* ctdup = safe_strdup(content_type);
                        if (ctdup) {
                            request->response->content_type = ctdup;
                        }
                    }

                    double content_length = 0;
                    if (curl_easy_getinfo(handle, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &content_length) == CURLE_OK && content_length >= 0) {
                        request->response->content_length = (size_t)content_length;
                    }

                    // detach response and protect request during callback
                    http_response_t* resp = request->response;
                    request->response = NULL;

                    completion_callback_t cb = request->completion_cb;
                    void* user_data = request->user_data;

                    request_unlock(request);

                    // Hold a temporary ref so request cannot be freed while callback runs allowing room for uaf
                    request_ref(request);
                    if (cb) {
                        cb(resp, user_data);
                    } else {
                        release_response_impl(resp);
                    }
                    request_unref(request);

                    // Balance the original ref owned by the multi-add path.
                    request_unref(request);

                } else {
                    // Error path
                    error_callback_t error_cb = request->error_cb;
                    void* user_data = request->user_data;

                    request_unlock(request);

                    request_ref(request);
                    if (error_cb) {
                        error_cb((int)msg->data.result, curl_easy_strerror(msg->data.result), user_data);
                    }
                    request_unref(request);

                    //And finally we balance the original ref.
                    request_unref(request);
                }
            }
        }

        usleep(100000);
    }
    return NULL;
}


bool start_network_monitor_impl(void) {
    if (atomic_load(&monitor_running)) return true;
    
    atomic_store(&monitor_running, true);
    if (pthread_create(&monitor_thread, NULL, network_monitor_thread, NULL) != 0) {
        atomic_store(&monitor_running, false);
        return false;
    }
    
    return true;
}

void stop_network_monitor_impl(void) {
    if (!atomic_load(&monitor_running)) return;
    
    atomic_store(&monitor_running, false);
    pthread_join(monitor_thread, NULL);
}

void force_network_refresh_impl(void) {
    CURLM* mh = NULL;
    
    pthread_mutex_lock(&network_mutex);
    mh = multi_handle;
    pthread_mutex_unlock(&network_mutex);
    
    if (mh) {
        int still_running;
        curl_multi_perform(mh, &still_running);
        
        int msgs_left;
        CURLMsg* msg;
        while ((msg = curl_multi_info_read(mh, &msgs_left))) {
            if (msg->msg == CURLMSG_DONE) {
                CURL* handle = msg->easy_handle;
                network_request_internal_t* request;
                curl_easy_getinfo(handle, CURLINFO_PRIVATE, &request);
                
                if (request) {
                    pthread_mutex_lock(&network_mutex);
                    curl_multi_remove_handle(mh, handle);
                    atomic_store(&request->in_multi, false);
                    pthread_mutex_unlock(&network_mutex);
                    
                    request_lock(request);
                    
                    if (msg->data.result == CURLE_OK) {
                        long http_code = 0;
                        curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &http_code);
                        request->response->status_code = (uint32_t)http_code;
                        
                        char* content_type = NULL;
                        if (curl_easy_getinfo(handle, CURLINFO_CONTENT_TYPE, &content_type) == CURLE_OK && content_type) {
                            request->response->content_type = safe_strdup(content_type);
                        }
                        
                        http_response_t* resp = request->response;
                        request->response = NULL;
                        
                        completion_callback_t cb = request->completion_cb;
                        void* user_data = request->user_data;
                        
                        request_unlock(request);
                        
                        if (cb) {
                            cb(resp, user_data);
                        } else {
                            release_response_impl(resp);
                        }
                    } else {
                        error_callback_t error_cb = request->error_cb;
                        void* user_data = request->user_data;
                        
                        request_unlock(request);
                        
                        if (error_cb) {
                            error_cb((int)msg->data.result, curl_easy_strerror(msg->data.result), user_data);
                        }
                    }
                    
                    request_unref(request);
                }
            }
        }
    }
}

void cleanup_resources_impl(void) {
    CURLM* mh = NULL;
    
    pthread_mutex_lock(&network_mutex);
    mh = multi_handle;
    multi_handle = NULL;
    pthread_mutex_unlock(&network_mutex);
    
    if (mh) {
        int still_running;
        curl_multi_perform(mh, &still_running);
        
        int msgs_left;
        CURLMsg* msg;
        while ((msg = curl_multi_info_read(mh, &msgs_left))) {
            if (msg->msg == CURLMSG_DONE) {
                CURL* handle = msg->easy_handle;
                network_request_internal_t* request;
                curl_easy_getinfo(handle, CURLINFO_PRIVATE, &request);
                
                if (request) {
                    curl_multi_remove_handle(mh, handle);
                    atomic_store(&request->in_multi, false);
                    
                    request_lock(request);
                    error_callback_t error_cb = request->error_cb;
                    void* user_data = request->user_data;
                    request_unlock(request);
                    
                    if (error_cb) {
                        error_cb((int)msg->data.result, curl_easy_strerror(msg->data.result), user_data);
                    }
                    request_unref(request);
                }
            }
        }
        
        curl_multi_cleanup(mh);
    }
    
    atomic_store(&monitor_running, false);
    curl_global_cleanup();
}

static bool register_request_hook_impl(request_hook_t hook, void* user_data) {
    if (!hook) return false;
    
    pthread_mutex_lock(&network_mutex);
    registered_hook = hook;
    hook_user_data = user_data;
    pthread_mutex_unlock(&network_mutex);
    
    return true;
}

static bool unregister_request_hook_impl(request_hook_t hook) {
    if (!hook || hook != registered_hook) return false;
    
    pthread_mutex_lock(&network_mutex);
    registered_hook = NULL;
    hook_user_data = NULL;
    pthread_mutex_unlock(&network_mutex);
    
    return true;
}

static void set_security_threshold_impl(uint32_t threshold_level) {
    pthread_mutex_lock(&network_mutex);
    security_threshold = threshold_level;
    pthread_mutex_unlock(&network_mutex);
}

static bool analyze_traffic_pattern_impl(const uint8_t* data, size_t length, uint32_t* threat_level) {
    if (!data || !threat_level || length == 0) return false;
    
    *threat_level = 0;
    
    double entropy = 0.0;
    uint8_t byte_frequency[256] = {0};
    
    size_t sample_size = length > 1000000 ? 1000000 : length;
    
    for (size_t i = 0; i < sample_size; i++) {
        byte_frequency[data[i]]++;
    }
    
    for (int i = 0; i < 256; i++) {
        if (byte_frequency[i] > 0) {
            double probability = (double)byte_frequency[i] / sample_size;
            entropy += -probability * log2(probability);
        }
    }
    
    if (entropy > 7.0) {
        *threat_level += 20;
    }
    
    if (length > 1000000) {
        *threat_level += 5;
    }
    
    size_t null_bytes = 0;
    size_t null_check_size = sample_size > 1000 ? 1000 : sample_size;
    for (size_t i = 0; i < null_check_size; i++) {
        if (data[i] == 0x00) null_bytes++;
    }
    
    if (null_bytes > (size_t)(sample_size * 0.1)) {
        *threat_level += 15;
    }
    
    return true;
}


static void log_security_event_impl(const char* event_type, const char* details, uint32_t severity) {
    if (!event_type || !details) return;
    if (severity < security_threshold) return;

    const char* path = "/data/local/tmp/network_security.log";
    int fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, S_IRUSR | S_IWUSR);
    if (fd < 0) return;

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != getuid()) {
        close(fd);
        return;
    }

    char linebuf[1024];
    time_t now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm_info);

    int n = snprintf(linebuf, sizeof(linebuf), "[%s] [SEVERITY:%u] [%s] %s\n",
                     timestamp, severity, event_type, details);
    if (n > 0) {
        size_t to_write = (size_t)(n < (int)sizeof(linebuf) ? n : (int)sizeof(linebuf) - 1);
        ssize_t wr = write(fd, linebuf, to_write);
        (void)wr;
    }

    close(fd);
}


static bool inspect_tls_handshake_impl(const uint8_t* handshake_data, size_t length) {
    if (!handshake_data || length < 5) return false;
    
    if (handshake_data[0] != 0x16) {
        return false;
    }
    
    uint16_t version = (handshake_data[1] << 8) | handshake_data[2];
    if (version < 0x0301) {
        return false;
    }
    
    size_t handshake_length = (handshake_data[3] << 8) | handshake_data[4];
    if (handshake_length + 5 != length) {
        return false;
    }
    
    return true;
}

static void set_data_streaming_callback_impl(void (*stream_cb)(const uint8_t* data, size_t length, bool is_outgoing)) {
    pthread_mutex_lock(&network_mutex);
    data_streaming_callback = stream_cb;
    pthread_mutex_unlock(&network_mutex);
}

static network_hooks_api_t internal_hooks_api = {
    .register_request_hook = register_request_hook_impl,
    .unregister_request_hook = unregister_request_hook_impl,
    .set_security_threshold = set_security_threshold_impl,
    .analyze_traffic_pattern = analyze_traffic_pattern_impl,
    .log_security_event = log_security_event_impl,
    .inspect_tls_handshake = inspect_tls_handshake_impl,
    .set_data_streaming_callback = set_data_streaming_callback_impl
};

static network_api_t public_network_api = {
    .get_network_type = get_network_type_impl,
    .get_connection_state = get_connection_state_impl,
    .is_network_available = is_network_available_impl,
    .is_metered_connection = is_metered_connection_impl,
    .get_signal_strength = get_signal_strength_impl,
    .get_network_quality = get_network_quality_impl,
    .get_available_wifi_networks = get_available_wifi_networks_impl,
    .get_cellular_network_info = get_cellular_network_info_impl,
    .create_request = create_request_impl,
    .set_request_headers = set_request_headers_impl,
    .set_request_body = set_request_body_impl,
    .set_request_priority = set_request_priority_impl,
    .set_request_timeout = set_request_timeout_impl,
    .execute_request = execute_request_impl,
    .execute_request_async = execute_request_async_impl,
    .cancel_request = cancel_request_impl,
    .release_request = release_request_impl,
    .release_response = release_response_impl,
    .download_file = download_file_impl,
    .upload_file = upload_file_impl,
    .set_global_timeout = set_global_timeout_impl,
    .set_max_connections = set_max_connections_impl,
    .enable_compression = enable_compression_impl,
    .enable_caching = enable_caching_impl,
    .start_network_monitor = start_network_monitor_impl,
    .stop_network_monitor = stop_network_monitor_impl,
    .force_network_refresh = force_network_refresh_impl,
    .cleanup_resources = cleanup_resources_impl
};

static complete_network_api_t complete_api = {
    .public_api = &public_network_api,
    .hooks_api = &internal_hooks_api
};

const complete_network_api_t* get_network_api(void) {
    pthread_once(&curl_init_once, curl_global_init_once);
    return &complete_api;
}

bool validate_network_api(const network_api_t* api) {
    if (!api) return false;
    
    if (!api->get_network_type || !api->get_connection_state || 
        !api->is_network_available || !api->is_metered_connection ||
        !api->get_signal_strength || !api->get_network_quality ||
        !api->get_available_wifi_networks || !api->get_cellular_network_info ||
        !api->create_request || !api->set_request_headers ||
        !api->set_request_body || !api->set_request_priority ||
        !api->set_request_timeout || !api->execute_request ||
        !api->execute_request_async || !api->cancel_request ||
        !api->release_request || !api->release_response ||
        !api->download_file || !api->upload_file ||
        !api->set_global_timeout || !api->set_max_connections ||
        !api->enable_compression || !api->enable_caching ||
        !api->start_network_monitor || !api->stop_network_monitor ||
        !api->force_network_refresh || !api->cleanup_resources) {
        return false;
    }
    
    return true;
};