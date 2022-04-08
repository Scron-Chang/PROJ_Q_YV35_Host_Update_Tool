cmake_minimum_required(VERSION 3.12)
project(yv35_host_update)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/output)

MACRO(INCLUDE_SUBDIR targetdir)
FILE(GLOB files ${targetdir}/*)
FOREACH(file IN LISTS files)
    IF(IS_DIRECTORY ${file})
        include_directories(${file})
    ENDIF()
ENDFOREACH(file)
ENDMACRO()

add_compile_definitions(HAVE_CONFIG_H)

FILE(GLOB_RECURSE freeipmi_sources freeipmi-1.6.9/libfreeipmi/*.c)
FILE(GLOB freeipmi_common freeipmi-1.6.9/common/debugutil/*.c freeipmi-1.6.9/common/miscutil/*.c)
LIST(APPEND freeipmi_sources ${freeipmi_common})

FILE(GLOB app_sources src/*.c)

INCLUDE_SUBDIR(freeipmi-1.6.9)
INCLUDE_SUBDIR(freeipmi-1.6.9/common)
INCLUDE_SUBDIR(freeipmi-1.6.9/libfreeipmi)
include_directories(freeipmi-1.6.9)

add_executable(host_update ${freeipmi_sources} ${app_sources})
target_link_libraries(host_update m)
