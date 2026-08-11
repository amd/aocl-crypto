# Configure a true production child build, where enabling this parent test suite
# would otherwise change libalcp's C++ export surface.

foreach(required_var
        ALCP_SOURCE_DIR
        ALCP_PRODUCTION_BINARY_DIR
        ALCP_EXPORT_CHECKER
        ALCP_CPP_MANIFEST
        PYTHON_EXECUTABLE)
    if(NOT DEFINED ${required_var} OR "${${required_var}}" STREQUAL "")
        message(FATAL_ERROR "${required_var} is required")
    endif()
endforeach()

file(REMOVE_RECURSE "${ALCP_PRODUCTION_BINARY_DIR}")

set(configure_command
    "${CMAKE_COMMAND}"
    -S "${ALCP_SOURCE_DIR}"
    -B "${ALCP_PRODUCTION_BINARY_DIR}"
    -DALCP_BUILD_SHARED=ON
    -DALCP_BUILD_STATIC=OFF
    -DALCP_ENABLE_TESTS=OFF
    -DALCP_ENABLE_EXAMPLES=OFF
    -DALCP_ENABLE_BENCH=OFF
    -DALCP_HIDDEN_VISIBILITY=ON
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
    message(FATAL_ERROR "production child configure failed: ${configure_result}")
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" --build "${ALCP_PRODUCTION_BINARY_DIR}"
            --target alcp
    RESULT_VARIABLE build_result)
if(NOT build_result EQUAL 0)
    message(FATAL_ERROR "production child build failed: ${build_result}")
endif()

set(library "${ALCP_PRODUCTION_BINARY_DIR}/libalcp.so")
set(c_manifest "${ALCP_PRODUCTION_BINARY_DIR}/alcp_export_symbols.txt")
execute_process(
    COMMAND "${ALCP_SOURCE_DIR}/scripts/extract_alcp_export_symbols.sh"
            "${ALCP_SOURCE_DIR}/include/alcp"
    OUTPUT_FILE "${c_manifest}"
    RESULT_VARIABLE manifest_result)
if(NOT manifest_result EQUAL 0)
    message(FATAL_ERROR "production C manifest generation failed: ${manifest_result}")
endif()

execute_process(
    COMMAND "${PYTHON_EXECUTABLE}" "${ALCP_EXPORT_CHECKER}"
            --library "${library}"
            --c-manifest "${c_manifest}"
            --cpp-manifest "${ALCP_CPP_MANIFEST}"
            --cpp-exports-disabled
    RESULT_VARIABLE checker_result)
if(NOT checker_result EQUAL 0)
    message(FATAL_ERROR "production export validation failed: ${checker_result}")
endif()
