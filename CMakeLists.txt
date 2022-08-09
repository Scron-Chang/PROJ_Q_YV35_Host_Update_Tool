cmake_minimum_required(VERSION 3.5)
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
add_compile_options(-Wall)
add_definitions(-D_GNU_SOURCE)

# list code in src
FILE(GLOB app_sources src/*.c)

add_executable(host_update ${app_sources})

# link c math library
target_link_libraries(host_update m)
