#include "../../../include/core/registry/app_registry.h"

#include <stdatomic.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>

#ifdef __ANDROID__
#include <android/log.h>
#include <sys/mman.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#endif

#define GUARD_MAGIC 0x8F3A5C67B2E1D409ULL
#define REGISTRY_MAGIC 0xDEADBEEFCAFEBABEULL
#define FUNCTION_REGISTRY_MAGIC 0xCAFEBABEDEADBEEFULL
#define API_VALIDATION_MAGIC 0x12345678
#define FINGERPRINT_INPUT_SIZE 512
#define MAX_PROTECTED_REGIONS 16
#define FUNCTION_GUARD_MAGIC 0xF1E2D3C4B5A69788ULL

static app_registry_t global_registry = {0};
static function_registry_t global_function_registry = {0};
static _Atomic bool registry_locked = false;
static _Atomic bool function_registry_locked = false;
static _Atomic uint64_t registry_magic = 0;
static _Atomic uint64_t function_registry_magic = 0;
static _Atomic bool init_in_progress = false;
static _Atomic bool function_registry_init_in_progress = false;

#ifdef __ANDROID__
static pthread_mutex_t registry_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    void* start;
    size_t length;
    bool protected;
    bool owned_by_module;
} memory_region_t;

static memory_region_t protected_regions[MAX_PROTECTED_REGIONS];
static size_t protected_region_count = 0;

static unsigned char* hmac_key = NULL;
static _Atomic bool hmac_key_initialized = false;

static void android_secure_log(const char* tag, const char* message) {
    __android_log_write(ANDROID_LOG_WARN, tag, message);
}

static bool initialize_openssl(void) {
    static _Atomic bool openssl_initialized = false;
    bool expected = false;
    
    if (atomic_compare_exchange_strong(&openssl_initialized, &expected, true)) {
        if (OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL) != 1) {
            atomic_store(&openssl_initialized, false);
            return false;
        }
    }
    return atomic_load(&openssl_initialized);
}

static long get_page_size(void) {
    static long page_size = 0;
    if (page_size == 0) {
        page_size = sysconf(_SC_PAGESIZE);
        if (page_size <= 0) {
            page_size = 4096;
        }
    }
    return page_size;
}

static bool compute_page_aligned_region(void* addr, size_t len, uintptr_t* start_out, uintptr_t* end_out) {
    long page_size = get_page_size();
    if ((page_size & (page_size - 1)) != 0) {
        return false;
    }
    
    uintptr_t start = (uintptr_t)addr & ~(page_size - 1);
    uintptr_t end = ((uintptr_t)addr + len + page_size - 1) & ~(page_size - 1);
    
    if (end < start) {
        return false;
    }
    
    *start_out = start;
    *end_out = end;
    return true;
}

static bool regions_overlap(uintptr_t start1, uintptr_t end1, uintptr_t start2, uintptr_t end2) {
    return (start1 < end2) && (start2 < end1);
}

static bool add_protected_region_locked(void* start, size_t length, bool is_protected, bool owned_by_module) {
    if (protected_region_count >= MAX_PROTECTED_REGIONS) {
        return false;
    }
    
    protected_regions[protected_region_count].start = start;
    protected_regions[protected_region_count].length = length;
    protected_regions[protected_region_count].protected = is_protected;
    protected_regions[protected_region_count].owned_by_module = owned_by_module;
    protected_region_count++;
    return true;
}

static bool lock_and_protect_region(void* addr, size_t len, bool make_readonly, bool owned_by_module) {
    pthread_mutex_lock(&registry_mutex);
    
    uintptr_t start, end;
    if (!compute_page_aligned_region(addr, len, &start, &end)) {
        pthread_mutex_unlock(&registry_mutex);
        return false;
    }
    
    size_t region_len = end - start;
    
    if (mlock((void*)start, region_len) != 0) {
        pthread_mutex_unlock(&registry_mutex);
        return false;
    }
    
    if (make_readonly) {
        if (mprotect((void*)start, region_len, PROT_READ) != 0) {
            munlock((void*)start, region_len);
            pthread_mutex_unlock(&registry_mutex);
            return false;
        }
    }
    
    bool success = add_protected_region_locked((void*)start, region_len, make_readonly, owned_by_module);
    if (!success) {
        if (make_readonly) {
            mprotect((void*)start, region_len, PROT_READ | PROT_WRITE);
        }
        munlock((void*)start, region_len);
    }
    
    pthread_mutex_unlock(&registry_mutex);
    return success;
}

static bool temporarily_unprotect_regions_for_write(void* addr, size_t len) {
    pthread_mutex_lock(&registry_mutex);
    
    uintptr_t target_start, target_end;
    if (!compute_page_aligned_region(addr, len, &target_start, &target_end)) {
        pthread_mutex_unlock(&registry_mutex);
        return false;
    }
    
    bool found_any = false;
    bool success = true;
    
    for (size_t i = 0; i < protected_region_count; i++) {
        if (!protected_regions[i].owned_by_module) {
            continue;
        }
        
        uintptr_t region_start = (uintptr_t)protected_regions[i].start;
        uintptr_t region_end = region_start + protected_regions[i].length;
        
        if (regions_overlap(target_start, target_end, region_start, region_end)) {
            if (mprotect(protected_regions[i].start, protected_regions[i].length, PROT_READ | PROT_WRITE) != 0) {
                success = false;
                break;
            }
            protected_regions[i].protected = false;
            found_any = true;
        }
    }
    
    if (!success) {
        for (size_t i = 0; i < protected_region_count; i++) {
            if (!protected_regions[i].owned_by_module || !protected_regions[i].protected) {
                continue;
            }
            
            uintptr_t region_start = (uintptr_t)protected_regions[i].start;
            uintptr_t region_end = region_start + protected_regions[i].length;
            
            if (regions_overlap(target_start, target_end, region_start, region_end)) {
                mprotect(protected_regions[i].start, protected_regions[i].length, PROT_READ);
            }
        }
    }
    
    pthread_mutex_unlock(&registry_mutex);
    return found_any && success;
}

static bool restore_regions_protection(void* addr, size_t len) {
    pthread_mutex_lock(&registry_mutex);
    
    uintptr_t target_start, target_end;
    if (!compute_page_aligned_region(addr, len, &target_start, &target_end)) {
        pthread_mutex_unlock(&registry_mutex);
        return false;
    }
    
    bool found_any = false;
    bool success = true;
    
    for (size_t i = 0; i < protected_region_count; i++) {
        if (!protected_regions[i].owned_by_module || protected_regions[i].protected) {
            continue;
        }
        
        uintptr_t region_start = (uintptr_t)protected_regions[i].start;
        uintptr_t region_end = region_start + protected_regions[i].length;
        
        if (regions_overlap(target_start, target_end, region_start, region_end)) {
            if (mprotect(protected_regions[i].start, protected_regions[i].length, PROT_READ) != 0) {
                success = false;
                break;
            }
            protected_regions[i].protected = true;
            found_any = true;
        }
    }
    
    if (!success) {
        for (size_t i = 0; i < protected_region_count; i++) {
            if (!protected_regions[i].owned_by_module || protected_regions[i].protected) {
                continue;
            }
            
            uintptr_t region_start = (uintptr_t)protected_regions[i].start;
            uintptr_t region_end = region_start + protected_regions[i].length;
            
            if (regions_overlap(target_start, target_end, region_start, region_end)) {
                mprotect(protected_regions[i].start, protected_regions[i].length, PROT_READ | PROT_WRITE);
            }
        }
    }
    
    pthread_mutex_unlock(&registry_mutex);
    return found_any && success;
}

static void unlock_owned_regions(void) {
    pthread_mutex_lock(&registry_mutex);
    
    for (size_t i = 0; i < protected_region_count; i++) {
        if (!protected_regions[i].owned_by_module) {
            continue;
        }
        
        if (protected_regions[i].protected) {
            mprotect(protected_regions[i].start, protected_regions[i].length, PROT_READ | PROT_WRITE);
        }
        munlock(protected_regions[i].start, protected_regions[i].length);
        
        protected_regions[i].start = NULL;
        protected_regions[i].length = 0;
        protected_regions[i].protected = false;
        protected_regions[i].owned_by_module = false;
    }
    
    protected_region_count = 0;
    pthread_mutex_unlock(&registry_mutex);
}
#else
static void android_secure_log(const char* tag, const char* message) {}
static bool initialize_openssl(void) { return false; }
static bool lock_and_protect_region(void* addr, size_t len, bool make_readonly, bool owned_by_module) { return false; }
static bool temporarily_unprotect_regions_for_write(void* addr, size_t len) { return false; }
static bool restore_regions_protection(void* addr, size_t len) { return false; }
static void unlock_owned_regions(void) {}
#endif

static bool secure_random_bytes(void* buffer, size_t size) {
    if (!initialize_openssl()) {
        return false;
    }
    
#ifdef RAND_priv_bytes
    if (RAND_priv_bytes(buffer, size) != 1) {
        return false;
    }
#else
    if (RAND_bytes(buffer, size) != 1) {
        return false;
    }
#endif
    
    return true;
}

static void secure_zero(void* ptr, size_t len) {
    if (ptr == NULL || len == 0) return;
    
#ifdef __ANDROID__
    OPENSSL_cleanse(ptr, len);
#else
    volatile unsigned char* p = (volatile unsigned char*)ptr;
    while (len--) {
        *p++ = 0;
    }
#endif
}

static bool validate_api_structure(const arch_detector_api_t* api) {
    if (api == NULL) {
        return false;
    }
    
    if (api->get_arch_info == NULL ||
        api->get_abi == NULL ||
        api->is_arch_supported == NULL ||
        api->get_binary_path == NULL) {
        return false;
    }
    
    const char* abi = api->get_abi();
    if (abi == NULL) {
        return false;
    }
    
    size_t abi_len = strlen(abi);
    if (abi_len == 0 || abi_len > 64) {
        return false;
    }
    
    char test_path[512];
    const char* binary_path = api->get_binary_path(test_path);
    if (binary_path == NULL) {
        return false;
    }
    
    size_t path_len = strnlen(binary_path, sizeof(test_path) - 1);
    if (path_len == 0 || path_len > 256) {
        return false;
    }
    
    return true;
}


static bool compute_arch_fingerprint(const arch_detector_api_t* api, uint8_t* fingerprint) {
    if (api == NULL || fingerprint == NULL) return false;
    
    uint8_t buffer[FINGERPRINT_INPUT_SIZE];
    size_t offset = 0;
    const size_t buf_sz = sizeof(buffer);
    
    const char* api_version = "ARCH_DETECTOR_API_V1";
    size_t version_len = strlen(api_version);
    if (offset + version_len > buf_sz) return false;
    memcpy(buffer + offset, api_version, version_len);
    offset += version_len;
    
    const char* func_names = "get_arch_info|get_abi|is_arch_supported|get_binary_path";
    size_t names_len = strlen(func_names);
    if (offset + names_len > buf_sz) return false;
    memcpy(buffer + offset, func_names, names_len);
    offset += names_len;
    
    uint32_t api_magic = API_VALIDATION_MAGIC;
    if (offset + sizeof(api_magic) > buf_sz) return false;
    memcpy(buffer + offset, &api_magic, sizeof(api_magic));
    offset += sizeof(api_magic);
    
    const char* abi = api->get_abi();
    if (abi != NULL) {
        if (offset + 64 > buf_sz) return false;
        memset(buffer + offset, 0, 64);
        size_t abi_len = strnlen(abi, 63);
        if (abi_len > 0) {
            memcpy(buffer + offset, abi, abi_len);
        }
        offset += 64;
    }
    
    char dummy_path[2] = "";
    const char* binary_path = api->get_binary_path(dummy_path);
    if (binary_path != NULL) {
        if (offset + 256 > buf_sz) return false;
        memset(buffer + offset, 0, 256);
        size_t path_len = strnlen(binary_path, 255);
        if (path_len > 0) {
            memcpy(buffer + offset, binary_path, path_len);
        }
        offset += 256;
    }
    
    if (offset > buf_sz) return false;
    
#ifdef __ANDROID__
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        return false;
    }
    
    bool success = false;
    if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(md_ctx, buffer, offset) == 1) {
        unsigned int md_len = ARCH_FINGERPRINT_SIZE;
        success = (EVP_DigestFinal_ex(md_ctx, fingerprint, &md_len) == 1 && md_len == ARCH_FINGERPRINT_SIZE);
    }
    
    EVP_MD_CTX_free(md_ctx);
    return success;
#else
    return false;
#endif
}

static inline uint32_t host_to_little_endian32(uint32_t value) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return value;
#else
    return __builtin_bswap32(value);
#endif
}

static inline uint64_t host_to_little_endian64(uint64_t value) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return value;
#else
    return __builtin_bswap64(value);
#endif
}


static bool build_canonical_buffer(const app_registry_t* reg, uint8_t* buf, size_t buf_size, size_t* out_len) {
    if (!reg || !buf || !out_len || buf_size < 256) {
        return false;
    }
    
    memset(buf, 0, buf_size);
    size_t off = 0;
    const size_t buf_sz = buf_size;
    
    uint32_t version_le = host_to_little_endian32(reg->version);

    if (off + sizeof(version_le) > buf_sz) return false;
    memcpy(buf + off, &version_le, sizeof(version_le));
    off += sizeof(version_le);
    

    if (off + APP_VERSION_MAX > buf_sz) return false;
    memcpy(buf + off, reg->app_version, APP_VERSION_MAX);
    off += APP_VERSION_MAX;
    

    if (off + ARCH_FINGERPRINT_SIZE > buf_sz) return false;
    memcpy(buf + off, reg->arch_fingerprint, ARCH_FINGERPRINT_SIZE);
    off += ARCH_FINGERPRINT_SIZE;
    
    uint64_t guard_le = host_to_little_endian64(reg->guard_magic);

    if (off + sizeof(guard_le) > buf_sz) return false;
    memcpy(buf + off, &guard_le, sizeof(guard_le));
    off += sizeof(guard_le);
    
    *out_len = off;
    return off <= buf_sz;
}

static bool build_function_registry_canonical_buffer(const function_registry_t* reg, uint8_t* buf, size_t buf_size, size_t* out_len) {
    if (!reg || !buf || !out_len || buf_size < 1024) {
        return false;
    }
    
    memset(buf, 0, buf_size);
    size_t off = 0;
    const size_t buf_sz = buf_size;
    
    uint64_t count_le = host_to_little_endian64(reg->count);
    if (off + sizeof(count_le) > buf_sz) return false;
    memcpy(buf + off, &count_le, sizeof(count_le));
    off += sizeof(count_le);
    
    uint64_t guard_le = host_to_little_endian64(reg->guard_magic);
    if (off + sizeof(guard_le) > buf_sz) return false;
    memcpy(buf + off, &guard_le, sizeof(guard_le));
    off += sizeof(guard_le);
    
    for (size_t i = 0; i < reg->count && i < MAX_SECURE_FUNCTIONS; i++) {
        const secure_function_t* func = &reg->functions[i];
        

        if (off + FUNCTION_NAME_MAX > buf_sz) return false;
        size_t name_len = strnlen(func->name, FUNCTION_NAME_MAX - 1);
        memset(buf + off, 0, FUNCTION_NAME_MAX);
        memcpy(buf + off, func->name, name_len);
        off += FUNCTION_NAME_MAX;
        
        if (off + FUNCTION_SIGNATURE_MAX > buf_sz) return false;
        size_t sig_len = strnlen(func->signature, FUNCTION_SIGNATURE_MAX - 1);
        memset(buf + off, 0, FUNCTION_SIGNATURE_MAX);
        memcpy(buf + off, func->signature, sig_len);
        off += FUNCTION_SIGNATURE_MAX;
        
        if (off + MODULE_NAME_MAX > buf_sz) return false;
        size_t mod_len = strnlen(func->module_name, MODULE_NAME_MAX - 1);
        memset(buf + off, 0, MODULE_NAME_MAX);
        memcpy(buf + off, func->module_name, mod_len);
        off += MODULE_NAME_MAX;
        
        uint64_t func_guard_le = host_to_little_endian64(func->guard_magic);
        if (off + sizeof(func_guard_le) > buf_sz) return false;
        memcpy(buf + off, &func_guard_le, sizeof(func_guard_le));
        off += sizeof(func_guard_le);
        
        uint8_t enabled = func->enabled ? 1 : 0;
        if (off + sizeof(enabled) > buf_sz) return false;
        memcpy(buf + off, &enabled, sizeof(enabled));
        off += sizeof(enabled);
    }
    
    *out_len = off;
    return off <= buf_sz;
}

static bool allocate_secure_hmac_key(void) {
#ifdef __ANDROID__
    long page_size = get_page_size();
    if (page_size <= 0) return false;
    
    size_t key_size = 32;
    size_t aligned_size = ((key_size + page_size - 1) / page_size) * page_size;
    if (aligned_size < key_size) return false;
    
    void* key_mem = mmap(NULL, aligned_size, PROT_READ | PROT_WRITE, 
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (key_mem == MAP_FAILED) {
        return false;
    }
    
    hmac_key = (unsigned char*)key_mem;
    
    if (!secure_random_bytes(hmac_key, key_size)) {
        secure_zero(hmac_key, aligned_size);
        munmap(key_mem, aligned_size);
        hmac_key = NULL;
        return false;
    }
    
    if (!lock_and_protect_region(hmac_key, aligned_size, true, true)) {
        secure_zero(hmac_key, aligned_size);
        munmap(key_mem, aligned_size);
        hmac_key = NULL;
        return false;
    }
    
    atomic_store_explicit(&hmac_key_initialized, true, memory_order_release);
    return true;
#else
    return false;
#endif
}

static bool compute_registry_hmac_locked(const app_registry_t* reg, unsigned char* out) {
#ifdef __ANDROID__
    if (!atomic_load_explicit(&hmac_key_initialized, memory_order_acquire) || hmac_key == NULL) {
        return false;
    }
    
    uint8_t key_copy[32];
    memcpy(key_copy, hmac_key, 32);
    
    uint8_t canonical_buf[256];
    size_t canonical_len = 0;
    bool success = false;
    
    if (build_canonical_buffer(reg, canonical_buf, sizeof(canonical_buf), &canonical_len)) {
        int key_len = (int)sizeof(key_copy);
        unsigned int hmac_len = (unsigned int)EVP_MD_size(EVP_sha256());
        const unsigned char* result = HMAC(EVP_sha256(), 
                                          key_copy, key_len,
                                          canonical_buf, canonical_len,
                                          out, &hmac_len);
        
        success = (result != NULL && hmac_len == EVP_MD_size(EVP_sha256()));
    }
    
    secure_zero(canonical_buf, sizeof(canonical_buf));
    secure_zero(key_copy, sizeof(key_copy));
    return success;
#else
    return false;
#endif
}

static bool compute_function_registry_hmac_locked(const function_registry_t* reg, unsigned char* out) {
#ifdef __ANDROID__
    if (!atomic_load_explicit(&hmac_key_initialized, memory_order_acquire) || hmac_key == NULL) {
        return false;
    }
    
    uint8_t key_copy[32];
    memcpy(key_copy, hmac_key, 32);
    
    uint8_t canonical_buf[2048];
    size_t canonical_len = 0;
    bool success = false;
    
    if (build_function_registry_canonical_buffer(reg, canonical_buf, sizeof(canonical_buf), &canonical_len)) {
        int key_len = (int)sizeof(key_copy);
        unsigned int hmac_len = (unsigned int)EVP_MD_size(EVP_sha256());
        const unsigned char* result = HMAC(EVP_sha256(), 
                                          key_copy, key_len,
                                          canonical_buf, canonical_len,
                                          out, &hmac_len);
        
        success = (result != NULL && hmac_len == EVP_MD_size(EVP_sha256()));
    }
    
    secure_zero(canonical_buf, sizeof(canonical_buf));
    secure_zero(key_copy, sizeof(key_copy));
    return success;
#else
    return false;
#endif
}


static bool compute_function_fingerprint(secure_function_t* func) {
    if (!func || !func->function_ptr) return false;
    
#ifdef __ANDROID__
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        return false;
    }
    
    uint8_t buffer[FINGERPRINT_INPUT_SIZE];
    size_t offset = 0;
    const size_t buf_sz = sizeof(buffer);
    
    size_t name_len = strnlen(func->name, FUNCTION_NAME_MAX - 1);
    if (offset + name_len > buf_sz) {
        EVP_MD_CTX_free(md_ctx);
        return false;
    }
    memcpy(buffer + offset, func->name, name_len);
    offset += name_len;
    
    size_t sig_len = strnlen(func->signature, FUNCTION_SIGNATURE_MAX - 1);
    if (offset + sig_len > buf_sz) {
        EVP_MD_CTX_free(md_ctx);
        return false;
    }
    memcpy(buffer + offset, func->signature, sig_len);
    offset += sig_len;
    
    size_t mod_len = strnlen(func->module_name, MODULE_NAME_MAX - 1);
    if (offset + mod_len > buf_sz) {
        EVP_MD_CTX_free(md_ctx);
        return false;
    }
    memcpy(buffer + offset, func->module_name, mod_len);
    offset += mod_len;
    
    uint64_t guard_le = host_to_little_endian64(func->guard_magic);
    if (offset + sizeof(guard_le) > buf_sz) {
        EVP_MD_CTX_free(md_ctx);
        return false;
    }
    memcpy(buffer + offset, &guard_le, sizeof(guard_le));
    offset += sizeof(guard_le);
    
    uint64_t ptr_hash = (uint64_t)(uintptr_t)func->function_ptr;
    uint64_t ptr_hash_le = host_to_little_endian64(ptr_hash);
    if (offset + sizeof(ptr_hash_le) > buf_sz) {
        EVP_MD_CTX_free(md_ctx);
        return false;
    }
    memcpy(buffer + offset, &ptr_hash_le, sizeof(ptr_hash_le));
    offset += sizeof(ptr_hash_le);
    
    bool success = false;
    if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(md_ctx, buffer, offset) == 1) {
        unsigned int md_len = 32;
        success = (EVP_DigestFinal_ex(md_ctx, func->fingerprint, &md_len) == 1 && md_len == 32);
    }
    
    EVP_MD_CTX_free(md_ctx);
    secure_zero(buffer, sizeof(buffer));
    return success;
#else
    return false;
#endif
}

static void secure_wipe_hmac_key(void) {
#ifdef __ANDROID__
    pthread_mutex_lock(&registry_mutex);
    
    if (atomic_load_explicit(&hmac_key_initialized, memory_order_acquire) && hmac_key != NULL) {
        long page_size = get_page_size();
        size_t aligned_size = ((32 + page_size - 1) / page_size) * page_size;
        
        temporarily_unprotect_regions_for_write(hmac_key, aligned_size);
        secure_zero(hmac_key, aligned_size);
        munmap(hmac_key, aligned_size);
        hmac_key = NULL;
        atomic_store_explicit(&hmac_key_initialized, false, memory_order_release);
    }
    
    pthread_mutex_unlock(&registry_mutex);
#endif
}

static bool constant_time_compare(const uint8_t* a, const uint8_t* b, size_t len) {
    if (a == NULL || b == NULL) return false;
    
#ifdef __ANDROID__
    return CRYPTO_memcmp(a, b, len) == 0;
#else
    uint8_t result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
#endif
}

static bool internal_verify_integrity(void) {
#ifdef __ANDROID__
    int trylock_rc = pthread_mutex_trylock(&registry_mutex);
    bool locked_by_us = (trylock_rc == 0);
    if (trylock_rc != 0 && trylock_rc != EBUSY) {
        return false;
    }
#endif
    
    if (!atomic_load_explicit(&registry_locked, memory_order_acquire)) {
#ifdef __ANDROID__
        if (locked_by_us) pthread_mutex_unlock(&registry_mutex);
#endif
        return false;
    }
    
    if (atomic_load_explicit(&registry_magic, memory_order_acquire) != REGISTRY_MAGIC) {
#ifdef __ANDROID__
        if (locked_by_us) pthread_mutex_unlock(&registry_mutex);
#endif
        return false;
    }
    
    if (global_registry.guard_magic != GUARD_MAGIC) {
#ifdef __ANDROID__
        if (locked_by_us) pthread_mutex_unlock(&registry_mutex);
#endif
        return false;
    }
    
    unsigned char computed_hmac[32];
    bool hmac_valid = false;
    
#ifdef __ANDROID__
    bool hmac_success = compute_registry_hmac_locked(&global_registry, computed_hmac);
#else
    bool hmac_success = false;
#endif
    
    if (hmac_success) {
        hmac_valid = constant_time_compare(computed_hmac, global_registry.hmac, 32);
    }
    
    secure_zero(computed_hmac, sizeof(computed_hmac));
    
#ifdef __ANDROID__
    if (locked_by_us) pthread_mutex_unlock(&registry_mutex);
#endif
    return hmac_valid;
}

static bool internal_verify_function_registry_integrity(void) {
#ifdef __ANDROID__
    int trylock_rc = pthread_mutex_trylock(&registry_mutex);
    bool locked_by_us = (trylock_rc == 0);
    if (trylock_rc != 0 && trylock_rc != EBUSY) {
        return false;
    }
#endif
    
    if (!atomic_load_explicit(&function_registry_locked, memory_order_acquire)) {
#ifdef __ANDROID__
        if (locked_by_us) pthread_mutex_unlock(&registry_mutex);
#endif
        return false;
    }
    
    if (atomic_load_explicit(&function_registry_magic, memory_order_acquire) != FUNCTION_REGISTRY_MAGIC) {
#ifdef __ANDROID__
        if (locked_by_us) pthread_mutex_unlock(&registry_mutex);
#endif
        return false;
    }
    
    if (global_function_registry.guard_magic != GUARD_MAGIC) {
#ifdef __ANDROID__
        if (locked_by_us) pthread_mutex_unlock(&registry_mutex);
#endif
        return false;
    }
    
    for (size_t i = 0; i < global_function_registry.count && i < MAX_SECURE_FUNCTIONS; i++) {
        if (global_function_registry.functions[i].guard_magic != FUNCTION_GUARD_MAGIC) {
#ifdef __ANDROID__
            if (locked_by_us) pthread_mutex_unlock(&registry_mutex);
#endif
            return false;
        }
    }
    
    unsigned char computed_hmac[32];
    bool hmac_valid = false;
    
#ifdef __ANDROID__
    bool hmac_success = compute_function_registry_hmac_locked(&global_function_registry, computed_hmac);
#else
    bool hmac_success = false;
#endif
    
    if (hmac_success) {
        hmac_valid = constant_time_compare(computed_hmac, global_function_registry.registry_hmac, 32);
    }
    
    secure_zero(computed_hmac, sizeof(computed_hmac));
    
#ifdef __ANDROID__
    if (locked_by_us) pthread_mutex_unlock(&registry_mutex);
#endif
    return hmac_valid;
}

static bool validate_function_call(const secure_function_t* func) {
    if (!func) return false;
    
    if (func->guard_magic != FUNCTION_GUARD_MAGIC) {
        return false;
    }
    
    if (!func->enabled) {
        return false;
    }
    
    if (!func->function_ptr) {
        return false;
    }
    
    secure_function_t temp_func;
    memcpy(&temp_func, func, sizeof(secure_function_t));
    memset(temp_func.fingerprint, 0, sizeof(temp_func.fingerprint));
    
    uint8_t computed_fingerprint[32];
    if (!compute_function_fingerprint(&temp_func)) {
        secure_zero(&temp_func, sizeof(temp_func));
        return false;
    }
    
    memcpy(computed_fingerprint, temp_func.fingerprint, 32);
    secure_zero(&temp_func, sizeof(temp_func));
    
    bool valid = constant_time_compare(computed_fingerprint, func->fingerprint, 32);
    secure_zero(computed_fingerprint, sizeof(computed_fingerprint));
    return valid;
}

bool get_app_registry_copy(app_registry_t* out) {
    if (out == NULL) return false;
    
#ifdef __ANDROID__
    pthread_mutex_lock(&registry_mutex);
#endif
    
    if (!internal_verify_integrity()) {
#ifdef __ANDROID__
        pthread_mutex_unlock(&registry_mutex);
#endif
        return false;
    }
    
    memcpy(out, &global_registry, sizeof(app_registry_t));
    
#ifdef __ANDROID__
    pthread_mutex_unlock(&registry_mutex);
#endif
    return true;
}

void initialize_app_registry(const arch_detector_api_t* arch_api) {
    bool expected = false;
    if (!atomic_compare_exchange_strong_explicit(&init_in_progress, &expected, true, 
                                               memory_order_acq_rel, memory_order_acquire)) {
        return;
    }
    
    bool initialization_success = false;
    
#ifdef __ANDROID__
    pthread_mutex_lock(&registry_mutex);
#endif
    
    if (atomic_load(&registry_locked)) {
        initialization_success = true;
        goto cleanup;
    }
    
    if (!validate_api_structure(arch_api)) {
        goto cleanup;
    }
    
    uint8_t arch_fingerprint[ARCH_FINGERPRINT_SIZE];
    if (!compute_arch_fingerprint(arch_api, arch_fingerprint)) {
        goto cleanup;
    }
    
    if (!allocate_secure_hmac_key()) {
        secure_zero(arch_fingerprint, sizeof(arch_fingerprint));
        goto cleanup;
    }
    
    app_registry_t temp_registry;
    memset(&temp_registry, 0, sizeof(temp_registry));
    temp_registry.version = 1;
    strncpy(temp_registry.app_version, "1.0.0", APP_VERSION_MAX - 1);
    temp_registry.app_version[APP_VERSION_MAX - 1] = '\0';
    memcpy(temp_registry.arch_fingerprint, arch_fingerprint, ARCH_FINGERPRINT_SIZE);
    temp_registry.guard_magic = GUARD_MAGIC;
    
#ifdef __ANDROID__
    if (!compute_registry_hmac_locked(&temp_registry, temp_registry.hmac)) {
#else
    if (false) {
#endif
        secure_wipe_hmac_key();
        secure_zero(arch_fingerprint, sizeof(arch_fingerprint));
        goto cleanup;
    }
    
    memcpy(&global_registry, &temp_registry, sizeof(global_registry));
    secure_zero(arch_fingerprint, sizeof(arch_fingerprint));
    
    if (!lock_and_protect_region(&global_registry, sizeof(global_registry), true, true)) {
        secure_wipe_hmac_key();
        goto cleanup;
    }
    
    atomic_store_explicit(&registry_magic, REGISTRY_MAGIC, memory_order_release);
    atomic_store_explicit(&registry_locked, true, memory_order_release);
    initialization_success = true;

cleanup:
#ifdef __ANDROID__
    pthread_mutex_unlock(&registry_mutex);
#endif
    
    if (!initialization_success) {
        secure_wipe_hmac_key();
        unlock_owned_regions();
        memset(&global_registry, 0, sizeof(global_registry));
    }
    
    atomic_store_explicit(&init_in_progress, false, memory_order_release);
}

bool is_registry_locked(void) {
    return atomic_load_explicit(&registry_locked, memory_order_acquire) && 
           internal_verify_integrity();
}

void cleanup_app_registry(void) {
    bool expected = false;
    if (!atomic_compare_exchange_strong_explicit(&init_in_progress, &expected, true, 
                                               memory_order_acq_rel, memory_order_acquire)) {
        return;
    }
    
#ifdef __ANDROID__
    pthread_mutex_lock(&registry_mutex);
#endif
    
    if (atomic_load(&registry_locked)) {
        temporarily_unprotect_regions_for_write(&global_registry, sizeof(global_registry));
        memset(&global_registry, 0, sizeof(global_registry));
        
        secure_wipe_hmac_key();
        unlock_owned_regions();
        
        atomic_store_explicit(&registry_locked, false, memory_order_release);
        atomic_store_explicit(&registry_magic, 0, memory_order_release);
    }
    
#ifdef __ANDROID__
    pthread_mutex_unlock(&registry_mutex);
#endif
    
    atomic_store_explicit(&init_in_progress, false, memory_order_release);
}

bool initialize_function_registry(void) {
    bool expected = false;
    if (!atomic_compare_exchange_strong_explicit(&function_registry_init_in_progress, &expected, true, 
                                               memory_order_acq_rel, memory_order_acquire)) {
        return false;
    }
    
    bool initialization_success = false;
    
#ifdef __ANDROID__
    pthread_mutex_lock(&registry_mutex);
#endif
    
    if (atomic_load(&function_registry_locked)) {
        initialization_success = true;
        goto cleanup;
    }
    
    if (!atomic_load(&hmac_key_initialized)) {
        goto cleanup;
    }
    
    memset(&global_function_registry, 0, sizeof(function_registry_t));
    global_function_registry.guard_magic = GUARD_MAGIC;
    
#ifdef __ANDROID__
    if (!compute_function_registry_hmac_locked(&global_function_registry, global_function_registry.registry_hmac)) {
#else
    if (false) {
#endif
        goto cleanup;
    }
    
    if (!lock_and_protect_region(&global_function_registry, sizeof(function_registry_t), true, true)) {
        goto cleanup;
    }
    
    atomic_store_explicit(&function_registry_magic, FUNCTION_REGISTRY_MAGIC, memory_order_release);
    atomic_store_explicit(&function_registry_locked, true, memory_order_release);
    initialization_success = true;

cleanup:
#ifdef __ANDROID__
    pthread_mutex_unlock(&registry_mutex);
#endif
    
    if (!initialization_success) {
        memset(&global_function_registry, 0, sizeof(function_registry_t));
    }
    
    atomic_store_explicit(&function_registry_init_in_progress, false, memory_order_release);
    return initialization_success;
}

void* get_secure_function(const char* function_name) {
    if (!function_name || !atomic_load(&function_registry_locked)) {
        return NULL;
    }
    
    size_t name_len = strnlen(function_name, FUNCTION_NAME_MAX);
    if (name_len == 0 || name_len >= FUNCTION_NAME_MAX) {
        return NULL;
    }
    
#ifdef __ANDROID__
    pthread_mutex_lock(&registry_mutex);
#endif
    
    if (!internal_verify_function_registry_integrity()) {
#ifdef __ANDROID__
        pthread_mutex_unlock(&registry_mutex);
#endif
        return NULL;
    }
    
    void* result = NULL;
    for (size_t i = 0; i < global_function_registry.count && i < MAX_SECURE_FUNCTIONS; i++) {
        secure_function_t* func = &global_function_registry.functions[i];
        
        if (strncmp(func->name, function_name, FUNCTION_NAME_MAX) == 0) {
            if (validate_function_call(func)) {
                result = func->function_ptr;
            }
            break;
        }
    }
    
#ifdef __ANDROID__
    pthread_mutex_unlock(&registry_mutex);
#endif
    return result;
}

bool register_secure_function(const char* name, const char* signature, void* function_ptr, const char* module_name) {
    if (!name || !signature || !function_ptr || !module_name || !atomic_load(&function_registry_locked)) {
        return false;
    }
    
    size_t name_len = strnlen(name, FUNCTION_NAME_MAX - 1);
    size_t sig_len = strnlen(signature, FUNCTION_SIGNATURE_MAX - 1);
    size_t mod_len = strnlen(module_name, MODULE_NAME_MAX - 1);
    
    if (name_len == 0 || name_len >= FUNCTION_NAME_MAX ||
        sig_len == 0 || sig_len >= FUNCTION_SIGNATURE_MAX ||
        mod_len == 0 || mod_len >= MODULE_NAME_MAX) {
        return false;
    }
    
#ifdef __ANDROID__
    pthread_mutex_lock(&registry_mutex);
#endif
    
    if (!internal_verify_function_registry_integrity()) {
#ifdef __ANDROID__
        pthread_mutex_unlock(&registry_mutex);
#endif
        return false;
    }
    
    if (global_function_registry.count >= MAX_SECURE_FUNCTIONS) {
#ifdef __ANDROID__
        pthread_mutex_unlock(&registry_mutex);
#endif
        return false;
    }
    
    for (size_t i = 0; i < global_function_registry.count; i++) {
        if (strncmp(global_function_registry.functions[i].name, name, FUNCTION_NAME_MAX) == 0) {
#ifdef __ANDROID__
            pthread_mutex_unlock(&registry_mutex);
#endif
            return false;
        }
    }
    
    secure_function_t new_func;
    memset(&new_func, 0, sizeof(secure_function_t));
    
    strncpy(new_func.name, name, FUNCTION_NAME_MAX - 1);
    new_func.name[FUNCTION_NAME_MAX - 1] = '\0';
    
    strncpy(new_func.signature, signature, FUNCTION_SIGNATURE_MAX - 1);
    new_func.signature[FUNCTION_SIGNATURE_MAX - 1] = '\0';
    
    strncpy(new_func.module_name, module_name, MODULE_NAME_MAX - 1);
    new_func.module_name[MODULE_NAME_MAX - 1] = '\0';
    
    new_func.function_ptr = function_ptr;
    new_func.enabled = true;
    new_func.guard_magic = FUNCTION_GUARD_MAGIC;
    
    if (!compute_function_fingerprint(&new_func)) {
#ifdef __ANDROID__
        pthread_mutex_unlock(&registry_mutex);
#endif
        secure_zero(&new_func, sizeof(new_func));
        return false;
    }
    
    size_t index = global_function_registry.count;
    memcpy(&global_function_registry.functions[index], &new_func, sizeof(secure_function_t));
    global_function_registry.count++;
    
    secure_zero(&new_func, sizeof(new_func));
    
#ifdef __ANDROID__
    if (!compute_function_registry_hmac_locked(&global_function_registry, global_function_registry.registry_hmac)) {
        memset(global_function_registry.registry_hmac, 0, sizeof(global_function_registry.registry_hmac));
        global_function_registry.count--;
        memset(&global_function_registry.functions[index], 0, sizeof(secure_function_t));
        pthread_mutex_unlock(&registry_mutex);
        return false;
    }
    
    pthread_mutex_unlock(&registry_mutex);
#endif
    
    return true;
}

bool verify_function_registry_integrity(void) {
    return atomic_load(&function_registry_locked) && internal_verify_function_registry_integrity();
}

void cleanup_function_registry(void) {
    bool expected = false;
    if (!atomic_compare_exchange_strong_explicit(&function_registry_init_in_progress, &expected, true, 
                                               memory_order_acq_rel, memory_order_acquire)) {
        return;
    }
    
#ifdef __ANDROID__
    pthread_mutex_lock(&registry_mutex);
#endif
    
    if (atomic_load(&function_registry_locked)) {
        temporarily_unprotect_regions_for_write(&global_function_registry, sizeof(function_registry_t));
        memset(&global_function_registry, 0, sizeof(function_registry_t));
        
        atomic_store_explicit(&function_registry_locked, false, memory_order_release);
        atomic_store_explicit(&function_registry_magic, 0, memory_order_release);
    }
    
#ifdef __ANDROID__
    pthread_mutex_unlock(&registry_mutex);
#endif
    
    atomic_store_explicit(&function_registry_init_in_progress, false, memory_order_release);
}

bool is_function_registry_locked(void) {
    return atomic_load_explicit(&function_registry_locked, memory_order_acquire) && 
           internal_verify_function_registry_integrity();
}

bool lock_function_registry_memory(void) {
#ifdef __ANDROID__
    return lock_and_protect_region(&global_function_registry, sizeof(function_registry_t), true, true);
#else
    return false;
#endif
}