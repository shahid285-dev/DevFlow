#ifndef APP_REGISTRY_H
#define APP_REGISTRY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif


#define APP_VERSION_MAX 32
#define ARCH_FINGERPRINT_SIZE 32


typedef struct {
    const char* arch_name;          
    const char* platform_name;     
    const char* abi;
    bool is_64bit;                  
    bool is_little_endian;          
    bool is_supported;              
} arch_info_t;


typedef struct arch_detector_api_t {
    arch_info_t (*get_arch_info)(void);
    const char* (*get_abi)(void);
    bool (*is_arch_supported)(void);
    const char* (*get_binary_path)(const char* base_name);
} arch_detector_api_t;


typedef struct {
    uint32_t version;                           
    char app_version[APP_VERSION_MAX];          
    uint8_t arch_fingerprint[ARCH_FINGERPRINT_SIZE]; 
    uint8_t hmac[32];      
    uint64_t guard_magic;       
} app_registry_t;


__attribute__((visibility("default")))
bool get_app_registry_copy(app_registry_t* out);

__attribute__((visibility("default")))
void initialize_app_registry(const arch_detector_api_t* arch_api);


__attribute__((visibility("default")))
bool is_registry_locked(void);

__attribute__((visibility("default")))
void cleanup_app_registry(void);

#ifdef __cplusplus
}
#endif

#endif 