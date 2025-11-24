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
    
    // Initialize the main app registry
    initialize_app_registry(arch_api);
    
    if (!is_registry_locked()) {
        printf("Registry failed to initialize securely\n");
        cleanup_app_registry();
        return 1;
    }
    

    if (!initialize_function_registry()) {
        printf("Function registry failed to initialize\n");
        cleanup_app_registry();
        return 1;
    }
    
    if (!is_function_registry_locked()) {
        printf("Function registry failed to lock securely\n");
        cleanup_function_registry();
        cleanup_app_registry();
        return 1;
    }
    
    app_registry_t registry_copy;
    if (!get_app_registry_copy(&registry_copy)) {
        printf("Registry access denied - integrity violation\n");
        cleanup_function_registry();
        cleanup_app_registry();
        return 1;
    }
    
    printf("Registry initialized successfully\n");
    printf("App Version: %s\n", registry_copy.app_version);
    

    cleanup_function_registry();
    cleanup_app_registry();
    
    return 0;
}