cmake_minimum_required(VERSION 3.12)
project(yv35_host_update)

MACRO(INCLUDE_SUBDIR targetdir)
FILE(GLOB files ${targetdir}/*)
FOREACH(file IN LISTS files)
    IF(IS_DIRECTORY ${file})
        include_directories(${file})
    ENDIF()
ENDFOREACH(file)
ENDMACRO()

# set ouput folder name
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/output)

# define macro to include config.h
add_compile_definitions(HAVE_CONFIG_H)
add_compile_definitions(_GNU_SOURCE)

# list neccessary code in freeipmi 
FILE(GLOB_RECURSE freeipmi_sources freeipmi-1.6.9/libfreeipmi/*.c)
FILE(GLOB freeipmi_common freeipmi-1.6.9/common/debugutil/*.c freeipmi-1.6.9/common/miscutil/*.c)
LIST(APPEND freeipmi_sources ${freeipmi_common})

# list code in src
FILE(GLOB app_sources src/*.c)

# set output file name and add code
add_executable(host_update ${freeipmi_sources} ${app_sources})

# include directories of header
INCLUDE_SUBDIR(freeipmi-1.6.9)
INCLUDE_SUBDIR(freeipmi-1.6.9/common)
INCLUDE_SUBDIR(freeipmi-1.6.9/libfreeipmi)
include_directories(freeipmi-1.6.9 include)

# link c math library
target_link_libraries(host_update m)
