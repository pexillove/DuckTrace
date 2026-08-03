cmake_minimum_required(VERSION 3.22.1)

project(qbdi_trace)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 路径配置（可通过 -D 覆盖）
set(QBDI_HOME ${QBDI_HOME} CACHE PATH "QBDI Android 包根目录 (包含 local/ 子目录)")
if(NOT QBDI_HOME)
    set(QBDI_HOME "${CMAKE_SOURCE_DIR}/../usr")
endif()

set(FRIDA_INC ${FRIDA_INC} CACHE PATH "frida-gum.h 所在目录")
set(FRIDA_LIB ${FRIDA_LIB} CACHE PATH "libfrida-gum.a 完整路径")

if(NOT EXISTS "${FRIDA_LIB}")
    set(FRIDA_LIB "/home/duck/NewCode/Android/DEV/qbdi_demo/app/src/main/libs/${ANDROID_ABI}/libfrida-gum.a")
endif()
if(NOT EXISTS "${FRIDA_INC}")
    set(FRIDA_INC "/home/duck/NewCode/Android/DEV/qbdi_demo/app/src/main/include")
endif()

# QBDI 动态库 (编译期链接，运行时推送到设备)
add_library(QBDI SHARED IMPORTED)
set_target_properties(QBDI PROPERTIES
    IMPORTED_LOCATION "${QBDI_HOME}/local/lib/libQBDI.so"
)

# frida-gum 静态库
add_library(frida-gum STATIC IMPORTED)
set_target_properties(frida-gum PROPERTIES
    IMPORTED_LOCATION "${FRIDA_LIB}"
)

add_library(trace SHARED
    trace_impl.cpp
    raw_logger.cpp
)

target_include_directories(trace PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${QBDI_HOME}/local/include
    ${FRIDA_INC}
)

target_link_libraries(trace
    QBDI
    frida-gum
    android
    log
    dl
    m
)
