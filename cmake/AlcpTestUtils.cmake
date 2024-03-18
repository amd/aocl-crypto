# Copyright (C) 2024, Advanced Micro Devices. All rights reserved.
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

function(alcp_add_valgrind_check_test test_name test_binary)
    find_program(VALGRIND "valgrind")
    # add more valgrind options here
    set(VALGRIND_ARGS "--leak-check=full")
    add_test(${test_name}_valgrind ${VALGRIND} ${VALGRIND_ARGS} ${test_binary})
endfunction(alcp_add_valgrind_check_test)

function(alcp_add_integration_tests test_name test_binary)
    set(IPP_ARGS "-i")
    set(OPENSSL_ARGS "-o")
    gtest_discover_tests(${test_name} TARGET ${test_binary})
    if(ENABLE_TESTS_IPP_API)
        gtest_discover_tests(${test_name} TARGET ${test_binary} EXTRA_ARGS ${IPP_ARGS} TEST_SUFFIX ".ipp")
    endif(ENABLE_TESTS_IPP_API)
    if (ENABLE_TESTS_OPENSSL_API)
        gtest_discover_tests(${test_name} TARGET ${test_binary} EXTRA_ARGS ${OPENSSL_ARGS} TEST_SUFFIX ".openssl")
    endif(ENABLE_TESTS_OPENSSL_API)
endfunction(alcp_add_integration_tests)

# for aes ciphers, it needs cipher mode as an extra arg
# FIXME: merge these two functions at one point
function(alcp_add_integration_tests_cipher test_name test_binary mode)
    set(IPP_ARGS "-i")
    set(OPENSSL_ARGS "-o")
    gtest_discover_tests(${test_name} TARGET ${test_binary} TEST_SUFFIX ".${mode}")
    if(ENABLE_TESTS_IPP_API)
        gtest_discover_tests(${test_name} TARGET ${test_binary} EXTRA_ARGS ${IPP_ARGS} TEST_SUFFIX ".${mode}.ipp")
    endif(ENABLE_TESTS_IPP_API)
    if (ENABLE_TESTS_OPENSSL_API)
        gtest_discover_tests(${test_name} TARGET ${test_binary} EXTRA_ARGS ${OPENSSL_ARGS} TEST_SUFFIX ".${mode}.openssl")
    endif(ENABLE_TESTS_OPENSSL_API)
endfunction(alcp_add_integration_tests_cipher)