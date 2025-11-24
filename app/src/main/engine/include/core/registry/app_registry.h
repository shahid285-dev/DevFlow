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
#define MAX_SECURE_FUNCTIONS 512
#define FUNCTION_NAME_MAX 64
#define FUNCTION_SIGNATURE_MAX 128
#define MODULE_NAME_MAX 32

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

typedef struct {
    void* function_ptr;
    char name[FUNCTION_NAME_MAX];
    char signature[FUNCTION_SIGNATURE_MAX];
    char module_name[MODULE_NAME_MAX];
    uint8_t fingerprint[32];
    bool enabled;
    uint64_t guard_magic;
} secure_function_t;

typedef struct {
    secure_function_t functions[MAX_SECURE_FUNCTIONS];
    size_t count;
    uint8_t registry_hmac[32];
    uint64_t guard_magic;
    atomic_bool locked;
} function_registry_t;

__attribute__((visibility("default")))
bool get_app_registry_copy(app_registry_t* out);

__attribute__((visibility("default")))
void initialize_app_registry(const arch_detector_api_t* arch_api);

__attribute__((visibility("default")))
bool is_registry_locked(void);

__attribute__((visibility("default")))
void cleanup_app_registry(void);

__attribute__((visibility("default")))
bool initialize_function_registry(void);

__attribute__((visibility("default")))
void* get_secure_function(const char* function_name);

__attribute__((visibility("default")))
bool register_secure_function(const char* name, const char* signature, void* function_ptr, const char* module_name);

__attribute__((visibility("default")))
bool verify_function_registry_integrity(void);

__attribute__((visibility("default")))
void cleanup_function_registry(void);

__attribute__((visibility("default")))
bool is_function_registry_locked(void);

#define REGISTER_FUNCTION(func_ptr, module) \
    register_secure_function(#func_ptr, __FUNCTION_SIGNATURE__, (void*)func_ptr, module)

__attribute__((visibility("hidden")))
bool compute_function_fingerprint(secure_function_t* func);

__attribute__((visibility("hidden")))
bool lock_function_registry_memory(void);

__attribute__((visibility("hidden")))
bool validate_function_call(const secure_function_t* func);

#ifdef __cplusplus
}
#endif

#endif