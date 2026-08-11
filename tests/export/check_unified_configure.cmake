# Verify export tests configure correctly when ALCP is a subdirectory.

foreach(required_var ALCP_SOURCE_DIR ALCP_UNIFIED_ROOT)
    if(NOT DEFINED ${required_var} OR "${${required_var}}" STREQUAL "")
        message(FATAL_ERROR "${required_var} is required")
    endif()
endforeach()

set(parent_source "${ALCP_UNIFIED_ROOT}/source")
set(parent_binary "${ALCP_UNIFIED_ROOT}/build")
file(REMOVE_RECURSE "${ALCP_UNIFIED_ROOT}")
file(MAKE_DIRECTORY "${parent_source}")

file(WRITE "${parent_source}/CMakeLists.txt"
"cmake_minimum_required(VERSION 3.26)\n"
"project(alcp_unified_probe LANGUAGES C CXX)\n"
"set(ALCP_BUILD_SHARED ON CACHE BOOL \"\" FORCE)\n"
"set(ALCP_BUILD_STATIC OFF CACHE BOOL \"\" FORCE)\n"
"set(ALCP_ENABLE_TESTS ON CACHE BOOL \"\" FORCE)\n"
"set(ALCP_ENABLE_EXAMPLES OFF CACHE BOOL \"\" FORCE)\n"
"set(ALCP_ENABLE_BENCH OFF CACHE BOOL \"\" FORCE)\n"
"set(ALCP_EXPORT_TESTS_ONLY ON CACHE BOOL \"\" FORCE)\n"
"add_subdirectory(\"${ALCP_SOURCE_DIR}\" alcp)\n")

set(configure_command
    "${CMAKE_COMMAND}"
    -S "${parent_source}"
    -B "${parent_binary}"
    -DCMAKE_BUILD_TYPE=Release)
if(DEFINED ALCP_GENERATOR AND NOT "${ALCP_GENERATOR}" STREQUAL "")
    list(APPEND configure_command -G "${ALCP_GENERATOR}")
endif()
if(DEFINED ALCP_C_COMPILER AND NOT "${ALCP_C_COMPILER}" STREQUAL "")
    list(APPEND configure_command "-DCMAKE_C_COMPILER=${ALCP_C_COMPILER}")
endif()
if(DEFINED ALCP_CXX_COMPILER AND NOT "${ALCP_CXX_COMPILER}" STREQUAL "")
    list(APPEND configure_command "-DCMAKE_CXX_COMPILER=${ALCP_CXX_COMPILER}")
endif()
if(DEFINED ALCP_FETCHCONTENT_BASE_DIR
   AND NOT "${ALCP_FETCHCONTENT_BASE_DIR}" STREQUAL "")
    list(APPEND configure_command
         "-DFETCHCONTENT_BASE_DIR=${ALCP_FETCHCONTENT_BASE_DIR}")
endif()
if(DEFINED ALCP_OPENSSL_INSTALL_DIR
   AND NOT "${ALCP_OPENSSL_INSTALL_DIR}" STREQUAL "")
    list(APPEND configure_command
         "-DOPENSSL_INSTALL_DIR=${ALCP_OPENSSL_INSTALL_DIR}")
endif()

execute_process(
    COMMAND ${configure_command}
    RESULT_VARIABLE configure_result)
if(NOT configure_result EQUAL 0)
    message(FATAL_ERROR "unified add_subdirectory configure failed: ${configure_result}")
endif()
