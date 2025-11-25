#define _GNU_SOURCE 

#include "../../include/utils/logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stdatomic.h>

#if defined(_WIN32)
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
#else
    #include <pthread.h>
#endif


#define LOGGER_STACK_BUF 1024 
#define LOGGER_TIMESTAMP_SIZE 20 


static atomic_int g_enabled = 1;
static atomic_int g_level = LOG_LEVEL_DEBUG;
static atomic_int g_color = 1;
static atomic_int g_abort_on_fatal = 0;


static FILE* g_file_sink = NULL;
static logger_callback_t g_callback = NULL;
static void* g_callback_user = NULL;


#if defined(_WIN32)
    static INIT_ONCE g_init_once = INIT_ONCE_STATIC_INIT;
    static CRITICAL_SECTION g_mutex;
    static BOOL CALLBACK logger_init_once(PINIT_ONCE once, PVOID param, PVOID *context) {
        InitializeCriticalSection(&g_mutex);
        setvbuf(stdout, NULL, _IOLBF, 0);
        setvbuf(stderr, NULL, _IOLBF, 0);
        return TRUE;
    }
#else
    static pthread_once_t g_init_once = PTHREAD_ONCE_INIT;
    static pthread_mutex_t g_mutex;
    static void logger_init_once(void) {
        pthread_mutexattr_t attr;
        (void)pthread_mutexattr_init(&attr);
#if defined(PTHREAD_MUTEX_RECURSIVE)
        (void)pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
#elif defined(PTHREAD_MUTEX_RECURSIVE_NP)
        (void)pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE_NP);
#endif
        (void)pthread_mutex_init(&g_mutex, &attr);
        (void)pthread_mutexattr_destroy(&attr);
        setvbuf(stdout, NULL, _IOLBF, 0);
        setvbuf(stderr, NULL, _IOLBF, 0);
    }
#endif


static void lock_logger(void) {
#if defined(_WIN32)
    InitOnceExecuteOnce(&g_init_once, logger_init_once, NULL, NULL);
    EnterCriticalSection(&g_mutex);
#else
    pthread_once(&g_init_once, logger_init_once);
    pthread_mutex_lock(&g_mutex);
#endif
}
static void unlock_logger(void) {
#if defined(_WIN32)
    LeaveCriticalSection(&g_mutex);
#else
    pthread_mutex_unlock(&g_mutex);
#endif
}


static const char* level_to_string(LogLevel level) {
    switch(level) {
        case LOG_LEVEL_DEBUG: return "DEBUG";
        case LOG_LEVEL_INFO: return "INFO";
        case LOG_LEVEL_WARNING: return "WARN";
        case LOG_LEVEL_ERROR: return "ERROR";
        case LOG_LEVEL_CRITICAL: return "CRIT";
        case LOG_LEVEL_FATAL: return "FATAL";
        default: return "UNKNOWN";
    }
}

static const char* level_to_color(LogLevel level) {
    if (!atomic_load_explicit(&g_color, memory_order_relaxed)) return "";
#if defined(_WIN32)
 
#endif
    switch(level) {
        case LOG_LEVEL_DEBUG: return "\033[36m";
        case LOG_LEVEL_INFO: return "\033[32m";
        case LOG_LEVEL_WARNING: return "\033[33m";
        case LOG_LEVEL_ERROR: return "\033[31m";
        case LOG_LEVEL_CRITICAL: return "\033[35m";
        case LOG_LEVEL_FATAL: return "\033[1;31m";
        default: return "";
    }
}


static void format_timestamp(char out[LOGGER_TIMESTAMP_SIZE]) {
    time_t now = time(NULL);
#if defined(_WIN32)
    struct tm t;
    localtime_s(&t, &now);
    strftime(out, LOGGER_TIMESTAMP_SIZE, "%Y-%m-%d %H:%M:%S", &t);
#else
    struct tm t;
    localtime_r(&now, &t);
    strftime(out, LOGGER_TIMESTAMP_SIZE, "%Y-%m-%d %H:%M:%S", &t);
#endif
}


void logger_init(void) {
#if defined(_WIN32)
    InitOnceExecuteOnce(&g_init_once, logger_init_once, NULL, NULL);
#else
    pthread_once(&g_init_once, logger_init_once);
#endif
}

void logger_shutdown(void) {
    lock_logger();
    if (g_file_sink) {
        fflush(g_file_sink);
        fclose(g_file_sink);
        g_file_sink = NULL;
    }
    g_callback = NULL;
    g_callback_user = NULL;
    unlock_logger();
    
}

void logger_set_enabled(int enabled) {
    atomic_store_explicit(&g_enabled, enabled ? 1 : 0, memory_order_relaxed);
}

int logger_is_enabled(void) {
    return atomic_load_explicit(&g_enabled, memory_order_relaxed);
}

void logger_set_level(LogLevel level) {
    atomic_store_explicit(&g_level, (int)level, memory_order_relaxed);
}

LogLevel logger_get_level(void) {
    return (LogLevel)atomic_load_explicit(&g_level, memory_order_relaxed);
}

void logger_set_color_enabled(int enabled) {
    atomic_store_explicit(&g_color, enabled ? 1 : 0, memory_order_relaxed);
}

int logger_get_color_enabled(void) {
    return atomic_load_explicit(&g_color, memory_order_relaxed);
}

void logger_set_abort_on_fatal(int enabled) {
    atomic_store_explicit(&g_abort_on_fatal, enabled ? 1 : 0, memory_order_relaxed);
}

int logger_get_abort_on_fatal(void) {
    return atomic_load_explicit(&g_abort_on_fatal, memory_order_relaxed);
}

int logger_set_log_file(const char* path) {
    if (!path) return -1;
    lock_logger();

    FILE* f = fopen(path, "a"); 
    if (!f) {
        unlock_logger();
        return -1;
    }
    
    setvbuf(f, NULL, _IOLBF, 0);

    if (g_file_sink) {
        fflush(g_file_sink);
        fclose(g_file_sink);
    }
    g_file_sink = f;
    unlock_logger();
    return 0;
}

void logger_clear_log_file(void) {
    lock_logger();
    if (g_file_sink) {
        fflush(g_file_sink);
        fclose(g_file_sink);
        g_file_sink = NULL;
    }
    unlock_logger();
}

void logger_set_callback(logger_callback_t cb, void* user_data) {
    lock_logger();
    g_callback = cb;
    g_callback_user = user_data;
    unlock_logger();
}

void logger_clear_callback(void) {
    lock_logger();
    g_callback = NULL;
    g_callback_user = NULL;
    unlock_logger();
}

void logger_log(LogLevel level, const char* file, int line, const char* fmt, ...) {
    int enabled = atomic_load_explicit(&g_enabled, memory_order_relaxed);
    int cur_level = atomic_load_explicit(&g_level, memory_order_relaxed);
    if (!enabled || level < cur_level) return;

    va_list ap;
    va_start(ap, fmt);

    char stack_buf[LOGGER_STACK_BUF];
    va_list ap_copy;
    va_copy(ap_copy, ap);
    int needed = vsnprintf(stack_buf, sizeof(stack_buf), fmt, ap_copy);
    va_end(ap_copy);

    char* message = NULL;
    int message_len = 0;
    if (needed < 0) {
        strncpy(stack_buf, "(format error)", sizeof(stack_buf) - 1);
        stack_buf[sizeof(stack_buf) - 1] = '\0';
        message = stack_buf;
        message_len = (int)strlen(stack_buf);
    } else if ((size_t)needed < sizeof(stack_buf)) {
        message = stack_buf;
        message_len = needed;
    } else {
        size_t bufsize = (size_t)needed + 1;
        char* heap_buf = (char*)malloc(bufsize);
        if (!heap_buf) {
            strncpy(stack_buf, "(out of memory)", sizeof(stack_buf) - 1);
            stack_buf[sizeof(stack_buf) - 1] = '\0';
            message = stack_buf;
            message_len = (int)strlen(stack_buf);
        } else {
            va_list ap_copy2;
            va_copy(ap_copy2, ap);
            int nr = vsnprintf(heap_buf, bufsize, fmt, ap_copy2);
            va_end(ap_copy2);
            if (nr < 0) {
                strncpy(heap_buf, "(format error)", bufsize - 1);
                heap_buf[bufsize - 1] = '\0';
                message_len = (int)strlen(heap_buf);
            } else {
                message_len = nr;
            }
            message = heap_buf;
        }
    }
    va_end(ap);

    char timestamp[LOGGER_TIMESTAMP_SIZE];
    format_timestamp(timestamp);

    const char* level_str = level_to_string(level);
    const char* color = level_to_color(level);
    const char* reset = (atomic_load_explicit(&g_color, memory_order_relaxed) ? "\033[0m" : "");

    const char* filename = "unknown";
    char filename_buf[256];
    if (file) {
        const char* slash = strrchr(file, '/');
#if defined(_WIN32)
        const char* backslash = strrchr(file, '\\');
        if (backslash && (!slash || backslash > slash)) slash = backslash;
#endif
        if (slash) filename = slash + 1;
        else filename = file;
        strncpy(filename_buf, filename, sizeof(filename_buf) - 1);
        filename_buf[sizeof(filename_buf) - 1] = '\0';
        filename = filename_buf;
    }

    int final_needed = 0; {
        final_needed = snprintf(NULL, 0, "%s[%s] %s%s%s %s:%d - %s\n",
                                timestamp, level_str, color, level_str, reset,
                                filename, line, message);
    }
    char* final_buf = NULL;
    int final_len = 0;
    if (final_needed < 0) {
        final_buf = stack_buf;
        final_len = snprintf(final_buf, sizeof(stack_buf), "%s[%s] %s:%d - %s\n",
                             timestamp, level_str, filename, line, message);
    } else if ((size_t)final_needed + 1 <= sizeof(stack_buf)) {
        final_len = snprintf(stack_buf, sizeof(stack_buf), "%s[%s] %s%s%s %s:%d - %s\n",
                             timestamp, level_str, color, level_str, reset,
                             filename, line, message);
        final_buf = stack_buf;
    } else {
        size_t fsz = (size_t)final_needed + 1;
        final_buf = (char*)malloc(fsz);
        if (!final_buf) {
            final_len = snprintf(stack_buf, sizeof(stack_buf), "%s[%s] %s:%d - %s\n",
                                 timestamp, level_str, filename, line, message);
            final_buf = stack_buf;
        } else {
            final_len = snprintf(final_buf, fsz, "%s[%s] %s%s%s %s:%d - %s\n",
                                 timestamp, level_str, color, level_str, reset,
                                 filename, line, message);
        }
    }

    lock_logger();

    FILE* console_out = (level >= LOG_LEVEL_WARNING) ? stderr : stdout;
    if (final_len > 0) {
        fwrite(final_buf, 1, (size_t)final_len, console_out);
        if (level == LOG_LEVEL_FATAL) fflush(console_out);
    }

    if (g_file_sink) {
        if (final_len > 0) {
            fwrite(final_buf, 1, (size_t)final_len, g_file_sink);
            if (level == LOG_LEVEL_FATAL) fflush(g_file_sink);
        }
    }

    if (g_callback) {
        g_callback(level, timestamp, level_str, filename, line, final_buf, g_callback_user);
    }

    unlock_logger();

    if (message != stack_buf && message != NULL) {
        free(message);
    }
    if (final_buf != stack_buf && final_buf != NULL) {
        free(final_buf);
    }

    if (level == LOG_LEVEL_FATAL && atomic_load_explicit(&g_abort_on_fatal, memory_order_relaxed)) {
        abort();
    }
}