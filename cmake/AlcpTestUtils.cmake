# Copyright (C) 2024-2025, Advanced Micro Devices. All rights reserved.
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


include(CMakeParseArguments)
include(GoogleTest)

set(ALCP_TEST_DISCOVERY_TIMEOUT 60 CACHE STRING
    "Timeout (seconds) for gtest_discover_tests test enumeration")

function(alcp_add_valgrind_check_test test_name test_binary)
    message(STATUS "Generating tests to run using Valgrind Memchecks.. checking for valgrind installation")
    find_program(VALGRIND "valgrind")
    # if no installation found
    if (NOT VALGRIND)
        message(FATAL_ERROR "Valgrind installation not found, tests will not work!")
    endif()
    # add more valgrind options here
    set(VALGRIND_ARGS "--leak-check=full")
    # valgrind is supported only on unix platform
    if (UNIX)
        add_test(${test_name}_valgrind ${VALGRIND} ${VALGRIND_ARGS} ${test_binary})
        set_tests_properties(${test_name}_valgrind PROPERTIES LABELS "valgrind")
    endif()
endfunction(alcp_add_valgrind_check_test)

# alcp_add_integration_tests(test_name test_binary [MODE <mode>])
#
# Registers a gtest binary with CTest via gtest_discover_tests.
#
# Each test receives a single module label read from the caller-scoped variable
# ALCP_MODULE_LABEL (e.g. "cipher", "digest").
function(alcp_add_integration_tests test_name test_binary)
    set(options "")
    set(oneValueArgs MODE)
    set(multiValueArgs "")
    cmake_parse_arguments(PARSE_ARGV 2 ARG "${options}" "${oneValueArgs}" "${multiValueArgs}")

    set(IPP_ARGS "-i")
    set(OPENSSL_ARGS "-o")

    set(_label "${ALCP_MODULE_LABEL}")

    # Check if this is a cipher test by looking for "cipher" in test_name or test_binary
    string(FIND "${test_name}" "cipher" cipher_pos_name)
    string(FIND "${test_binary}" "cipher" cipher_pos_binary)

    if(cipher_pos_name GREATER_EQUAL 0 OR cipher_pos_binary GREATER_EQUAL 0)
        # This is a cipher test - mode is required
        if(NOT ARG_MODE)
            message(FATAL_ERROR "MODE argument is required for cipher tests (test: ${test_name})")
        endif()

        gtest_discover_tests(${test_name} TARGET ${test_binary} TEST_SUFFIX ".${ARG_MODE}" NO_PRETTY_VALUES NO_PRETTY_TYPES
            DISCOVERY_TIMEOUT ${ALCP_TEST_DISCOVERY_TIMEOUT}
            PROPERTIES LABELS "${_label}")
        if(ENABLE_TESTS_IPP_API)
            gtest_discover_tests(${test_name} TARGET ${test_binary} EXTRA_ARGS ${IPP_ARGS} TEST_SUFFIX ".${ARG_MODE}.ipp" NO_PRETTY_VALUES NO_PRETTY_TYPES
                DISCOVERY_TIMEOUT ${ALCP_TEST_DISCOVERY_TIMEOUT}
                PROPERTIES LABELS "${_label}")
        endif(ENABLE_TESTS_IPP_API)
        if(ENABLE_TESTS_OPENSSL_API)
            gtest_discover_tests(${test_name} TARGET ${test_binary} EXTRA_ARGS ${OPENSSL_ARGS} TEST_SUFFIX ".${ARG_MODE}.openssl" NO_PRETTY_VALUES NO_PRETTY_TYPES
                DISCOVERY_TIMEOUT ${ALCP_TEST_DISCOVERY_TIMEOUT}
                PROPERTIES LABELS "${_label}")
        endif(ENABLE_TESTS_OPENSSL_API)
    else()
        gtest_discover_tests(${test_name} TARGET ${test_binary} NO_PRETTY_VALUES NO_PRETTY_TYPES
            DISCOVERY_TIMEOUT ${ALCP_TEST_DISCOVERY_TIMEOUT}
            PROPERTIES LABELS "${_label}")
        if(ENABLE_TESTS_IPP_API)
            gtest_discover_tests(${test_name} TARGET ${test_binary} EXTRA_ARGS ${IPP_ARGS} TEST_SUFFIX ".ipp" NO_PRETTY_VALUES NO_PRETTY_TYPES
                DISCOVERY_TIMEOUT ${ALCP_TEST_DISCOVERY_TIMEOUT}
                PROPERTIES LABELS "${_label}")
        endif(ENABLE_TESTS_IPP_API)
        if(ENABLE_TESTS_OPENSSL_API)
            gtest_discover_tests(${test_name} TARGET ${test_binary} EXTRA_ARGS ${OPENSSL_ARGS} TEST_SUFFIX ".openssl" NO_PRETTY_VALUES NO_PRETTY_TYPES
                DISCOVERY_TIMEOUT ${ALCP_TEST_DISCOVERY_TIMEOUT}
                PROPERTIES LABELS "${_label}")
        endif(ENABLE_TESTS_OPENSSL_API)
    endif()
endfunction(alcp_add_integration_tests)
