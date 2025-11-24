#ifndef ARCHITECTURE_DETECTOR_H
#define ARCHITECTURE_DETECTOR_H

#include <stdint.h>
#include <stdbool.h>

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

const arch_detector_api_t* get_architecture_api(void);

#endif