FILE(GLOB_RECURSE app_sources ${CMAKE_SOURCE_DIR}/main/*.*)

idf_component_register(SRCS ${app_sources}
                       INCLUDE_DIRS "." "../include")
set(KCONFIG_PROJBUILD_DIR ${CMAKE_CURRENT_SOURCE_DIR})