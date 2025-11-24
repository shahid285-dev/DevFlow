#ifndef NETWORK_API_H
#define NETWORK_API_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    NETWORK_TYPE_UNKNOWN = 0,
    NETWORK_TYPE_WIFI,
    NETWORK_TYPE_CELLULAR,
    NETWORK_TYPE_ETHERNET,
    NETWORK_TYPE_VPN,
    NETWORK_TYPE_BLUETOOTH
} network_type_t;

typedef enum {
    CONNECTION_STATE_DISCONNECTED = 0,
    CONNECTION_STATE_CONNECTING,
    CONNECTION_STATE_CONNECTED,
    CONNECTION_STATE_DISCONNECTING,
    CONNECTION_STATE_SUSPENDED
} connection_state_t;

typedef enum {
    SECURITY_NONE = 0,
    SECURITY_WEP,
    SECURITY_WPA,
    SECURITY_WPA2,
    SECURITY_WPA3,
    SECURITY_EAP
} network_security_t;

typedef enum {
    HTTP_METHOD_GET = 0,
    HTTP_METHOD_POST,
    HTTP_METHOD_PUT,
    HTTP_METHOD_DELETE,
    HTTP_METHOD_HEAD,
    HTTP_METHOD_PATCH
} http_method_t;

typedef enum {
    REQUEST_PRIORITY_LOW = 0,
    REQUEST_PRIORITY_NORMAL,
    REQUEST_PRIORITY_HIGH,
    REQUEST_PRIORITY_URGENT
} request_priority_t;

typedef struct {
    uint32_t total_bytes;
    uint32_t transferred_bytes;
    uint64_t speed_bps;
    double progress;
    uint64_t estimated_time_remaining;
} transfer_progress_t;

typedef struct {
    uint32_t status_code;
    const char* content_type;
    size_t content_length;
    const char* headers;
    const uint8_t* body;
    size_t body_length;
} http_response_t;

typedef struct {
    uint32_t download_speed_bps;
    uint32_t upload_speed_bps;
    uint32_t latency_ms;
    uint32_t packet_loss;
    uint32_t jitter_ms;
} network_quality_t;

typedef struct {
    const char* ssid;
    const char* bssid;
    int32_t signal_strength;
    network_security_t security;
    uint32_t frequency;
    bool is_secured;
} wifi_network_info_t;

typedef struct {
    const char* carrier_name;
    int32_t signal_strength;
    uint32_t network_generation;
    bool is_roaming;
} cellular_network_info_t;

typedef void (*progress_callback_t)(const transfer_progress_t* progress, void* user_data);
typedef void (*completion_callback_t)(const http_response_t* response, void* user_data);
typedef void (*error_callback_t)(int error_code, const char* error_message, void* user_data);

typedef struct network_request_t network_request_t;

typedef struct {
    network_type_t (*get_network_type)(void);
    connection_state_t (*get_connection_state)(void);
    bool (*is_network_available)(void);
    bool (*is_metered_connection)(void);
    
    int32_t (*get_signal_strength)(void);
    network_quality_t (*get_network_quality)(void);
    
    wifi_network_info_t* (*get_available_wifi_networks)(size_t* count);
    cellular_network_info_t* (*get_cellular_network_info)(void);
    
    network_request_t* (*create_request)(http_method_t method, const char* url);
    void (*set_request_headers)(network_request_t* request, const char* headers);
    void (*set_request_body)(network_request_t* request, const uint8_t* data, size_t length);
    void (*set_request_priority)(network_request_t* request, request_priority_t priority);
    void (*set_request_timeout)(network_request_t* request, uint32_t timeout_ms);
    
    bool (*execute_request)(network_request_t* request, http_response_t** response);
    void (*execute_request_async)(network_request_t* request, 
                                 completion_callback_t completion_cb,
                                 progress_callback_t progress_cb,
                                 error_callback_t error_cb,
                                 void* user_data);
    
    void (*cancel_request)(network_request_t* request);
    void (*release_request)(network_request_t* request);
    void (*release_response)(http_response_t* response);
    
    bool (*download_file)(const char* url, const char* local_path, 
                         progress_callback_t progress_cb, void* user_data);
    bool (*upload_file)(const char* url, const char* local_path,
                       progress_callback_t progress_cb, void* user_data);
    
    void (*set_global_timeout)(uint32_t timeout_ms);
    void (*set_max_connections)(uint32_t max_connections);
    void (*enable_compression)(bool enable);
    void (*enable_caching)(bool enable);
    
    bool (*start_network_monitor)(void);
    void (*stop_network_monitor)(void);
    void (*force_network_refresh)(void);
    
    void (*cleanup_resources)(void);
} network_api_t;

typedef enum {
    HOOK_POINT_REQUEST_START = 0,
    HOOK_POINT_REQUEST_HEADERS,
    HOOK_POINT_REQUEST_BODY,
    HOOK_POINT_RESPONSE_START,
    HOOK_POINT_RESPONSE_HEADERS,
    HOOK_POINT_RESPONSE_BODY,
    HOOK_POINT_REQUEST_COMPLETE,
    HOOK_POINT_REQUEST_ERROR,
    HOOK_POINT_NETWORK_CHANGE,
    HOOK_POINT_SECURITY_ALERT
} hook_point_t;

typedef enum {
    HOOK_RESULT_CONTINUE = 0,
    HOOK_RESULT_BLOCK,
    HOOK_RESULT_MODIFY,
    HOOK_RESULT_RETRY
} hook_result_t;

typedef struct {
    const char* url;
    http_method_t method;
    const char* headers;
    const uint8_t* body;
    size_t body_length;
    uint32_t timestamp;
    const char* source_info;
} request_context_t;

typedef struct {
    uint32_t status_code;
    const char* headers;
    const uint8_t* body;
    size_t body_length;
    uint32_t timestamp;
} response_context_t;

typedef hook_result_t (*request_hook_t)(hook_point_t point, 
                                       const request_context_t* request,
                                       response_context_t* response,
                                       void* user_data);

typedef struct {
    bool (*register_request_hook)(request_hook_t hook, void* user_data);
    bool (*unregister_request_hook)(request_hook_t hook);
    void (*set_security_threshold)(uint32_t threshold_level);
    bool (*analyze_traffic_pattern)(const uint8_t* data, size_t length, uint32_t* threat_level);
    void (*log_security_event)(const char* event_type, const char* details, uint32_t severity);
    bool (*inspect_tls_handshake)(const uint8_t* handshake_data, size_t length);
    void (*set_data_streaming_callback)(void (*stream_cb)(const uint8_t* data, size_t length, bool is_outgoing));
} network_hooks_api_t;

typedef struct {
    const network_api_t* public_api;
    const network_hooks_api_t* hooks_api;
} complete_network_api_t;

const complete_network_api_t* get_network_api(void);
bool validate_network_api(const network_api_t* api);

#ifdef __cplusplus
}
#endif

#endif