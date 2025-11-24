/*
Devflow main entry point


*/

#include "app_registry.h"
#include "architecture_detector.h"
#include <stdio.h>

int main(void) {
    const arch_detector_api_t* arch_api = get_architecture_api();
    
    if (arch_api == NULL) {
        printf("Architecture API failed integrity check\n");
        return 1;
    }
    
    initialize_app_registry(arch_api);
    
    if (!is_registry_locked()) {
        printf("Registry failed to initialize securely\n");
        cleanup_app_registry();
        return 1;
    }
    
    app_registry_t registry_copy;
    if (!get_app_registry_copy(&registry_copy)) {
        printf("Registry access denied - integrity violation\n");
        cleanup_app_registry();
        return 1;
    }
    
    printf("Registry initialized and secured with OpenSSL\n");
    printf("Architecture: %s\n", registry_copy.arch->get_abi());
    
    cleanup_app_registry();
    return 0;
}