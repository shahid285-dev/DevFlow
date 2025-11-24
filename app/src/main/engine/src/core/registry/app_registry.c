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
#define API_VALIDATION_MAGIC 0x12345678
#define FINGERPRINT_INPUT_SIZE 512
#define MAX_PROTECTED_REGIONS 8

static app_registry_t global_registry = {0};
static _Atomic bool registry_locked = false;
static _Atomic uint64_t registry_magic = 0;
static _Atomic bool init_in_progress = false;

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
    for (size_t i = 0; i < protected_region_count; i++) {
        if (!protected_regions[i].owned_by_module) {
            continue;
        }
        
        uintptr_t region_start = (uintptr_t)protected_regions[i].start;
        uintptr_t region_end = region_start + protected_regions[i].length;
        
        if (regions_overlap(target_start, target_end, region_start, region_end)) {
            if (mprotect(protected_regions[i].start, protected_regions[i].length, PROT_READ | PROT_WRITE) != 0) {
                pthread_mutex_unlock(&registry_mutex);
                return false;
            }
            protected_regions[i].protected = false;
            found_any = true;
        }
    }
    
    pthread_mutex_unlock(&registry_mutex);
    return found_any;
}

static bool restore_regions_protection(void* addr, size_t len) {
    pthread_mutex_lock(&registry_mutex);
    
    uintptr_t target_start, target_end;
    if (!compute_page_aligned_region(addr, len, &target_start, &target_end)) {
        pthread_mutex_unlock(&registry_mutex);
        return false;
    }
    
    bool found_any = false;
    for (size_t i = 0; i < protected_region_count; i++) {
        if (!protected_regions[i].owned_by_module) {
            continue;
        }
        
        uintptr_t region_start = (uintptr_t)protected_regions[i].start;
        uintptr_t region_end = region_start + protected_regions[i].length;
        
        if (regions_overlap(target_start, target_end, region_start, region_end)) {
            if (mprotect(protected_regions[i].start, protected_regions[i].length, PROT_READ) != 0) {
                pthread_mutex_unlock(&registry_mutex);
                return false;
            }
            protected_regions[i].protected = true;
            found_any = true;
        }
    }
    
    pthread_mutex_unlock(&registry_mutex);
    return found_any;
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
    
    char test_path[2];
    const char* binary_path = api->get_binary_path(test_path);
    if (binary_path == NULL) {
        return false;
    }
    
    size_t path_len = strlen(binary_path);
    if (path_len == 0 || path_len > 256) {
        return false;
    }
    
    return true;
}

static bool compute_arch_fingerprint(const arch_detector_api_t* api, uint8_t* fingerprint) {
    if (api == NULL || fingerprint == NULL) return false;
    
    uint8_t buffer[FINGERPRINT_INPUT_SIZE];
    size_t offset = 0;
    const size_t max_offset = sizeof(buffer) - 1;
    
    const char* api_version = "ARCH_DETECTOR_API_V1";
    size_t version_len = strlen(api_version);
    if (offset + version_len > max_offset) return false;
    memcpy(buffer + offset, api_version, version_len);
    offset += version_len;
    
    const char* func_names = "get_arch_info|get_abi|is_arch_supported|get_binary_path";
    size_t names_len = strlen(func_names);
    if (offset + names_len > max_offset) return false;
    memcpy(buffer + offset, func_names, names_len);
    offset += names_len;
    
    uint32_t api_magic = API_VALIDATION_MAGIC;
    if (offset + sizeof(api_magic) > max_offset) return false;
    memcpy(buffer + offset, &api_magic, sizeof(api_magic));
    offset += sizeof(api_magic);
    
    const char* abi = api->get_abi();
    if (abi != NULL) {
        size_t abi_len = strnlen(abi, 64);
        if (offset + 64 > max_offset) return false;
        memset(buffer + offset, 0, 64);
        memcpy(buffer + offset, abi, abi_len);
        offset += 64;
    }
    
    char dummy_path[2] = "";
    const char* binary_path = api->get_binary_path(dummy_path);
    if (binary_path != NULL) {
        size_t path_len = strnlen(binary_path, 256);
        if (offset + 256 > max_offset) return false;
        memset(buffer + offset, 0, 256);
        memcpy(buffer + offset, binary_path, path_len);
        offset += 256;
    }
    
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
    const size_t max_off = buf_size - 1;
    
    uint32_t version_le = host_to_little_endian32(reg->version);
    if (off + sizeof(version_le) > max_off) return false;
    memcpy(buf + off, &version_le, sizeof(version_le));
    off += sizeof(version_le);
    
    if (off + APP_VERSION_MAX > max_off) return false;
    memcpy(buf + off, reg->app_version, APP_VERSION_MAX);
    off += APP_VERSION_MAX;
    
    if (off + ARCH_FINGERPRINT_SIZE > max_off) return false;
    memcpy(buf + off, reg->arch_fingerprint, ARCH_FINGERPRINT_SIZE);
    off += ARCH_FINGERPRINT_SIZE;
    
    uint64_t guard_le = host_to_little_endian64(reg->guard_magic);
    if (off + sizeof(guard_le) > max_off) return false;
    memcpy(buf + off, &guard_le, sizeof(guard_le));
    off += sizeof(guard_le);
    
    *out_len = off;
    return true;
}

static bool allocate_secure_hmac_key(void) {
#ifdef __ANDROID__
    long page_size = get_page_size();
    if (page_size <= 0) return false;
    
    size_t aligned_size = ((32 + page_size - 1) / page_size) * page_size;
    
    void* key_mem = mmap(NULL, aligned_size, PROT_READ | PROT_WRITE, 
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (key_mem == MAP_FAILED) {
        return false;
    }
    
    hmac_key = (unsigned char*)key_mem;
    
    if (!secure_random_bytes(hmac_key, 32)) {
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
    
    atomic_store(&hmac_key_initialized, true);
    return true;
#else
    return false;
#endif
}

static bool compute_registry_hmac_locked(const app_registry_t* reg, unsigned char* out) {
#ifdef __ANDROID__
    if (!atomic_load(&hmac_key_initialized) || hmac_key == NULL) {
        return false;
    }
    
    uint8_t key_copy[32];
    memcpy(key_copy, hmac_key, 32);
    
    uint8_t canonical_buf[256];
    size_t canonical_len = 0;
    bool success = false;
    
    if (build_canonical_buffer(reg, canonical_buf, sizeof(canonical_buf), &canonical_len)) {
        unsigned int hmac_len = 32;
        const unsigned char* result = HMAC(EVP_sha256(), 
                                          key_copy, 32,
                                          canonical_buf, canonical_len,
                                          out, &hmac_len);
        
        success = (result != NULL && hmac_len == 32);
    }
    
    secure_zero(canonical_buf, sizeof(canonical_buf));
    secure_zero(key_copy, sizeof(key_copy));
    return success;
#else
    return false;
#endif
}

static void secure_wipe_hmac_key(void) {
#ifdef __ANDROID__
    pthread_mutex_lock(&registry_mutex);
    
    if (atomic_load(&hmac_key_initialized) && hmac_key != NULL) {
        long page_size = get_page_size();
        size_t aligned_size = ((32 + page_size - 1) / page_size) * page_size;
        
        temporarily_unprotect_regions_for_write(hmac_key, aligned_size);
        secure_zero(hmac_key, aligned_size);
        munmap(hmac_key, aligned_size);
        hmac_key = NULL;
        atomic_store(&hmac_key_initialized, false);
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
    pthread_mutex_lock(&registry_mutex);
#endif
    
    if (!atomic_load_explicit(&registry_locked, memory_order_acquire)) {
#ifdef __ANDROID__
        pthread_mutex_unlock(&registry_mutex);
#endif
        return false;
    }
    
    if (atomic_load_explicit(&registry_magic, memory_order_acquire) != REGISTRY_MAGIC) {
#ifdef __ANDROID__
        pthread_mutex_unlock(&registry_mutex);
#endif
        return false;
    }
    
    if (global_registry.guard_magic != GUARD_MAGIC) {
#ifdef __ANDROID__
        pthread_mutex_unlock(&registry_mutex);
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
    pthread_mutex_unlock(&registry_mutex);
#endif
    return hmac_valid;
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
    
    if (atomic_load(&registry_locked)) {
        temporarily_unprotect_regions_for_write(&global_registry, sizeof(global_registry));
        memset(&global_registry, 0, sizeof(global_registry));
        
        secure_wipe_hmac_key();
        unlock_owned_regions();
        
        atomic_store_explicit(&registry_locked, false, memory_order_release);
        atomic_store_explicit(&registry_magic, 0, memory_order_release);
    }
    
    atomic_store_explicit(&init_in_progress, false, memory_order_release);
}