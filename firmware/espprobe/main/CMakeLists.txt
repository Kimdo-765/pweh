idf_component_register(SRCS "main.c" "usb_descriptors.c" "policy.c"
    INCLUDE_DIRS "." REQUIRES pweh_common esp_tinyusb esp_app_format app_update
    esp_partition esp_hw_support esp_system esp_timer bootloader_support)
idf_build_get_property(pweh_build_dir BUILD_DIR)
target_include_directories(${COMPONENT_LIB} PRIVATE "${pweh_build_dir}/generated")
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror)
