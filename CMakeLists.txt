# Blackbox Flight Data Logger
# ESP-IDF Component CMakeLists.txt
#
# This component uses a HAL architecture for platform portability.
# Core logic is in core/, HAL implementations in hal/

# For ESP-IDF, we compile the core + ESP HAL
idf_component_register(
    SRCS
        "core/blackbox_core.c"
        "hal/blackbox_hal_esp.c"
    INCLUDE_DIRS
        "."
        "include"
        "core"
        "hal"
    REQUIRES
        mbedtls
)

# Compiler warnings
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra)
