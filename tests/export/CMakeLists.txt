# Copyright (C) 2022-2026, Advanced Micro Devices. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 3. Neither the name of the copyright holder nor the names of its contributors
#    may be used to endorse or promote products derived from this software
# without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

IF(NOT TARGET alcp)
    MESSAGE(FATAL_ERROR "export tests require the enabled alcp shared target")
ENDIF()
IF(ENABLE_OPENSSL_COMPAT AND NOT TARGET openssl-compat)
    MESSAGE(FATAL_ERROR "ENABLE_OPENSSL_COMPAT is ON but openssl-compat target is missing")
ENDIF()
IF(ENABLE_IPP_COMPAT AND NOT TARGET ipp-compat)
    MESSAGE(FATAL_ERROR "ENABLE_IPP_COMPAT is ON but ipp-compat target is missing")
ENDIF()

find_package(Python3 3.9 REQUIRED COMPONENTS Interpreter)

set(ALCP_EXPORT_SYMBOLS_MANIFEST
    "${CMAKE_CURRENT_BINARY_DIR}/alcp_export_symbols.txt")

file(GLOB_RECURSE ALCP_PUBLIC_HEADERS CONFIGURE_DEPENDS
    "${ALCP_ROOT}/include/alcp/*.h")

add_custom_command(
    OUTPUT "${ALCP_EXPORT_SYMBOLS_MANIFEST}"
    COMMAND "${Python3_EXECUTABLE}"
            "${ALCP_ROOT}/scripts/extract_export_symbols.py"
            --kind alcp
            --output "${ALCP_EXPORT_SYMBOLS_MANIFEST}"
            "${ALCP_ROOT}/include/alcp"
    DEPENDS "${ALCP_ROOT}/scripts/extract_export_symbols.py"
            ${ALCP_PUBLIC_HEADERS}
    COMMENT "Generating ALCP export symbol manifest"
)

set(ALCP_EXPORT_CPP_EXCEPTIONS_MANIFEST
    "${CMAKE_CURRENT_BINARY_DIR}/alcp_export_cpp_exceptions.txt")

add_custom_command(
    OUTPUT "${ALCP_EXPORT_CPP_EXCEPTIONS_MANIFEST}"
    COMMAND ${CMAKE_COMMAND} -E copy
            "${CMAKE_CURRENT_SOURCE_DIR}/alcp_export_cpp_exceptions.txt"
            "${ALCP_EXPORT_CPP_EXCEPTIONS_MANIFEST}"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/alcp_export_cpp_exceptions.txt"
    COMMENT "Copying ALCP C++ export exception manifest"
)

add_custom_target(alcp_export_symbols_manifest
    DEPENDS "${ALCP_EXPORT_SYMBOLS_MANIFEST}"
            "${ALCP_EXPORT_CPP_EXCEPTIONS_MANIFEST}")

set(IPP_COMPAT_SYMBOLS_MANIFEST
    "${CMAKE_CURRENT_BINARY_DIR}/ipp_compat_symbols.txt")
set(IPP_COMPAT_SYMBOLS_SOURCE
    "${ALCP_ROOT}/lib/compat/ipp/ipp_compat_symbols.txt")

add_custom_command(
    OUTPUT "${IPP_COMPAT_SYMBOLS_MANIFEST}"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${IPP_COMPAT_SYMBOLS_SOURCE}"
            "${IPP_COMPAT_SYMBOLS_MANIFEST}"
    DEPENDS "${IPP_COMPAT_SYMBOLS_SOURCE}"
    COMMENT "Copying IPP compat export symbol manifest"
)

add_custom_target(ipp_export_symbols_manifest
    DEPENDS "${IPP_COMPAT_SYMBOLS_MANIFEST}")

set(LIBS_EXPORT gtest ${CMAKE_DL_LIBS})

IF(WIN32)
    add_executable(test_windows_exports test_windows_exports.cc)
    add_dependencies(test_windows_exports alcp alcp_export_symbols_manifest)
    target_compile_definitions(test_windows_exports PRIVATE
        ALCP_EXPORT_LIBRARY="$<TARGET_FILE:alcp>"
        ALCP_EXPORT_SYMBOLS_MANIFEST="${ALCP_EXPORT_SYMBOLS_MANIFEST}")

    IF(ENABLE_OPENSSL_COMPAT)
        add_dependencies(test_windows_exports openssl-compat)
        target_compile_definitions(test_windows_exports PRIVATE
            OPENSSL_COMPAT_LIB_PATH="$<TARGET_FILE:openssl-compat>")
    ENDIF()
    IF(ENABLE_IPP_COMPAT)
        add_dependencies(test_windows_exports ipp-compat ipp_export_symbols_manifest)
        target_compile_definitions(test_windows_exports PRIVATE
            IPP_COMPAT_LIB_PATH="$<TARGET_FILE:ipp-compat>"
            IPP_COMPAT_SYMBOLS_MANIFEST="${IPP_COMPAT_SYMBOLS_MANIFEST}")
    ENDIF()

    target_compile_options(test_windows_exports PUBLIC ${ALCP_WARNINGS})
    target_link_libraries(test_windows_exports gtest)
    gtest_add_tests(TARGET test_windows_exports TEST_LIST _windows_export_tests)
    set_tests_properties(${_windows_export_tests}
        PROPERTIES LABELS "export-alcp export-compat unit")
    RETURN()
ENDIF()

add_executable(test_alcp_exports test_alcp_exports.cc)
add_dependencies(test_alcp_exports alcp alcp_export_symbols_manifest)

target_include_directories(test_alcp_exports PRIVATE
    "${ALCP_ROOT}/include"
    "${ALCP_BINARY_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../include")

target_compile_definitions(test_alcp_exports PRIVATE
    ALCP_EXPORT_LIBRARY="$<TARGET_FILE:alcp>"
    ALCP_EXPORT_SYMBOLS_MANIFEST="${ALCP_EXPORT_SYMBOLS_MANIFEST}"
    ALCP_EXPORT_CPP_EXCEPTIONS_MANIFEST="${CMAKE_CURRENT_SOURCE_DIR}/alcp_export_cpp_exceptions.txt"
    ALCP_EXPORT_CHECKER="${ALCP_ROOT}/scripts/check_alcp_exports.py"
    ALCP_HIDDEN_VISIBILITY_ENABLED=$<BOOL:${ALCP_HIDDEN_VISIBILITY}>)

target_compile_options(test_alcp_exports PUBLIC ${ALCP_WARNINGS})
target_link_libraries(test_alcp_exports ${LIBS_EXPORT})

gtest_add_tests(TARGET test_alcp_exports TEST_LIST _alcp_export_tests)
set_tests_properties(${_alcp_export_tests} PROPERTIES LABELS "export-alcp unit")

IF(ENABLE_OPENSSL_COMPAT)
    add_executable(test_openssl_compat_exports test_openssl_compat_exports.cc)
    add_dependencies(test_openssl_compat_exports openssl-compat)

    target_include_directories(test_openssl_compat_exports PRIVATE
        "${ALCP_ROOT}/include"
        "${ALCP_BINARY_DIR}/include")

    target_compile_definitions(test_openssl_compat_exports PRIVATE
        OPENSSL_COMPAT_LIB_PATH="$<TARGET_FILE:openssl-compat>"
        ALCP_HIDDEN_VISIBILITY_ENABLED=$<BOOL:${ALCP_HIDDEN_VISIBILITY}>)

    target_compile_options(test_openssl_compat_exports PUBLIC ${ALCP_WARNINGS})
    target_link_libraries(test_openssl_compat_exports ${LIBS_EXPORT})

    gtest_add_tests(TARGET test_openssl_compat_exports TEST_LIST _ossl_export_tests)
    set_tests_properties(${_ossl_export_tests} PROPERTIES LABELS "export-compat unit")
ENDIF()

IF(ENABLE_IPP_COMPAT)
    add_executable(test_ipp_compat_exports test_ipp_compat_exports.cc)
    add_dependencies(test_ipp_compat_exports ipp-compat ipp_export_symbols_manifest)

    target_include_directories(test_ipp_compat_exports PRIVATE
        "${ALCP_ROOT}/include"
        "${ALCP_BINARY_DIR}/include")

    target_compile_definitions(test_ipp_compat_exports PRIVATE
        IPP_COMPAT_LIB_PATH="$<TARGET_FILE:ipp-compat>"
        IPP_COMPAT_SYMBOLS_MANIFEST="${IPP_COMPAT_SYMBOLS_MANIFEST}"
        ALCP_HIDDEN_VISIBILITY_ENABLED=$<BOOL:${ALCP_HIDDEN_VISIBILITY}>)

    target_compile_options(test_ipp_compat_exports PUBLIC ${ALCP_WARNINGS})
    target_link_libraries(test_ipp_compat_exports ${LIBS_EXPORT})

    gtest_add_tests(TARGET test_ipp_compat_exports TEST_LIST _ipp_export_tests)
    set_tests_properties(${_ipp_export_tests} PROPERTIES LABELS "export-compat unit")
ENDIF()

set(OPENSSL_COMPAT_TARGET_FILE "")
IF(ENABLE_OPENSSL_COMPAT)
    set(OPENSSL_COMPAT_TARGET_FILE "$<TARGET_FILE:openssl-compat>")
ENDIF()

set(IPP_COMPAT_TARGET_FILE "")
IF(ENABLE_IPP_COMPAT)
    set(IPP_COMPAT_TARGET_FILE "$<TARGET_FILE:ipp-compat>")
ENDIF()

add_test(
    NAME check_shared_exports
    COMMAND "${ALCP_ROOT}/scripts/run_check_shared_exports.sh"
            "${ALCP_ROOT}"
            "${CMAKE_CURRENT_BINARY_DIR}"
            "$<TARGET_FILE:alcp>"
            "$<BOOL:${ENABLE_OPENSSL_COMPAT}>"
            "${OPENSSL_COMPAT_TARGET_FILE}"
            "$<BOOL:${ENABLE_IPP_COMPAT}>"
            "${IPP_COMPAT_TARGET_FILE}"
            "$<BOOL:${ALCP_HIDDEN_VISIBILITY}>"
            "$<BOOL:${ALCP_INTERNAL_CPP_EXPORTS_ENABLED}>"
)
set_tests_properties(check_shared_exports PROPERTIES LABELS "export-alcp export-compat unit")

add_test(
    NAME check_export_checker_unit
    COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/test_check_alcp_exports.py")
set_tests_properties(check_export_checker_unit
    PROPERTIES LABELS "export-alcp unit")

add_test(
    NAME check_production_exports
    COMMAND "${CMAKE_COMMAND}"
        "-DALCP_SOURCE_DIR=${ALCP_ROOT}"
        "-DALCP_PRODUCTION_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}/production"
        "-DALCP_EXPORT_CHECKER=${ALCP_ROOT}/scripts/check_alcp_exports.py"
        "-DALCP_CPP_MANIFEST=${CMAKE_CURRENT_SOURCE_DIR}/alcp_export_cpp_exceptions.txt"
        "-DPYTHON_EXECUTABLE=${Python3_EXECUTABLE}"
        "-DALCP_GENERATOR=${CMAKE_GENERATOR}"
        "-DALCP_C_COMPILER=${CMAKE_C_COMPILER}"
        "-DALCP_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
        "-DALCP_FETCHCONTENT_BASE_DIR=${FETCHCONTENT_BASE_DIR}"
        "-DALCP_OPENSSL_INSTALL_DIR=${OPENSSL_INSTALL_DIR}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/check_production_exports.cmake")
set_tests_properties(check_production_exports PROPERTIES
    LABELS "export-alcp integration"
    RUN_SERIAL TRUE
    TIMEOUT 1200)

add_test(
    NAME check_unified_export_configure
    COMMAND "${CMAKE_COMMAND}"
        "-DALCP_SOURCE_DIR=${ALCP_ROOT}"
        "-DALCP_UNIFIED_ROOT=${CMAKE_CURRENT_BINARY_DIR}/unified"
        "-DALCP_GENERATOR=${CMAKE_GENERATOR}"
        "-DALCP_C_COMPILER=${CMAKE_C_COMPILER}"
        "-DALCP_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
        "-DALCP_FETCHCONTENT_BASE_DIR=${FETCHCONTENT_BASE_DIR}"
        "-DALCP_OPENSSL_INSTALL_DIR=${OPENSSL_INSTALL_DIR}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/check_unified_configure.cmake")
set_tests_properties(check_unified_export_configure PROPERTIES
    LABELS "export-alcp integration"
    RUN_SERIAL TRUE
    TIMEOUT 1200)
