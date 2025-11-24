#include "../../include/utils/architecture_detector.h"
#include <string.h>

typedef enum {
    ARCH_UNKNOWN = 0,
    ARCH_X86,
    ARCH_X86_64,
    ARCH_ARM,
    ARCH_ARM64,
    ARCH_ARMv7,
    ARCH_MIPS,
    ARCH_MIPS64
} architecture_type_t;

typedef enum {
    PLATFORM_UNKNOWN = 0,
    PLATFORM_LINUX,
    PLATFORM_ANDROID,
    PLATFORM_WINDOWS,
    PLATFORM_MACOS
} platform_type_t;

static bool is_little_endian(void) {
    const uint32_t test = 0x01020304;
    return ((const uint8_t*)&test)[0] == 0x04;
}

static uint8_t get_pointer_size(void) {
    return (uint8_t)(sizeof(void*) * 8);
}

static platform_type_t detect_platform(void) {
#if defined(__ANDROID__)
    return PLATFORM_ANDROID;
#elif defined(__linux__)
    return PLATFORM_LINUX;
#elif defined(_WIN32) || defined(_WIN64)
    return PLATFORM_WINDOWS;
#elif defined(__APPLE__) && defined(__MACH__)
    return PLATFORM_MACOS;
#else
    return PLATFORM_UNKNOWN;
#endif
}

static const char* get_platform_name(platform_type_t platform) {
    switch (platform) {
        case PLATFORM_LINUX: return "linux";
        case PLATFORM_ANDROID: return "android";
        case PLATFORM_WINDOWS: return "windows";
        case PLATFORM_MACOS: return "macos";
        default: return "unknown";
    }
}

static arch_info_t detect_architecture_impl(void) {
    arch_info_t info = {0};
    info.pointer_size = get_pointer_size();
    info.is_64bit = (info.pointer_size == 64);
    info.is_little_endian = is_little_endian();
    
    platform_type_t platform = detect_platform();
    info.platform_name = get_platform_name(platform);

#if defined(__aarch64__) || defined(_M_ARM64)
    info.arch_name = "arm64";
    info.abi = "arm64-v8a";
    info.is_supported = true;

#elif defined(__arm__) || defined(_M_ARM)
#if defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__) || defined(_M_ARM)
    info.arch_name = "armv7";
    info.abi = "armeabi-v7a";
#else
    info.arch_name = "arm";
    info.abi = "armeabi";
#endif
    info.is_supported = true;

#elif defined(__x86_64__) || defined(_M_X64)
    info.arch_name = "x86_64";
    info.abi = "x86_64";
    info.is_supported = true;

#elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
    info.arch_name = "x86";
    info.abi = "x86";
    info.is_supported = true;

#elif defined(__mips__)
#if defined(__mips64)
    info.arch_name = "mips64";
    info.abi = "mips64";
#else
    info.arch_name = "mips";
    info.abi = "mips";
#endif
    info.is_supported = false;

#else
    info.arch_name = "unknown";
    info.abi = "unknown";
    info.is_supported = false;
#endif

    if (platform == PLATFORM_ANDROID) {
        if (strcmp(info.arch_name, "arm64") == 0) {
            info.abi = "arm64-v8a";
        } else if (strcmp(info.arch_name, "armv7") == 0) {
            info.abi = "armeabi-v7a";
        }
    }

    return info;
}

static const char* get_abi_impl(void) {
    arch_info_t info = detect_architecture_impl();
    return info.abi;
}

static bool is_arch_supported_impl(void) {
    arch_info_t info = detect_architecture_impl();
    return info.is_supported;
}

static char binary_path_buffer[256];
static const char* get_binary_path_impl(const char* base_name) {
    arch_info_t info = detect_architecture_impl();
    const char* platform_str = (info.platform_name == "android") ? "android" : info.platform_name;
    snprintf(binary_path_buffer, sizeof(binary_path_buffer), "binaries/%s_%s_%s", base_name, platform_str, info.abi);
    return binary_path_buffer;
}

static const arch_detector_api_t arch_api = {
    .get_arch_info = detect_architecture_impl,
    .get_abi = get_abi_impl,
    .is_arch_supported = is_arch_supported_impl,
    .get_binary_path = get_binary_path_impl
};

const arch_detector_api_t* get_architecture_api(void) {
    return &arch_api;
}