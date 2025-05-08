 # Copyright (C) 2022-2024, Advanced Micro Devices. All rights reserved.
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


if (POLICY CMP0079) # Visibility
    cmake_policy(SET CMP0079 NEW)
endif(POLICY CMP0079)

Include(${CMAKE_SOURCE_DIR}/cmake/AlcpTestUtils.cmake)

# Basic sources and libs needed for ALCP
FILE(GLOB ALC_COMMON_SRC ${CMAKE_SOURCE_DIR}/tests/common/base/*.cc)
SET(ALC_BASE_FILES ${ALC_BASE_FILES}
            ${ALC_COMMON_SRC}
            ${CMAKE_SOURCE_DIR}/tests/cipher/base/alc_cipher.cc
            ${CMAKE_SOURCE_DIR}/tests/cipher/base/alc_cipher_aead.cc
            ${CMAKE_SOURCE_DIR}/tests/cipher/base/cipher.cc)

IF(WIN32)
    target_link_libraries(gmock PUBLIC gtest)
    target_link_libraries(gmock_main PUBLIC gtest_main)
ENDIF()

# If there is IPP, add IPP source and add IPP liberary
IF(ENABLE_TESTS_IPP_API)
    SET(EXTRA_SOURCES ${EXTRA_SOURCES} base/ipp_cipher.cc base/ipp_cipher_aead.cc)
ENDIF(ENABLE_TESTS_IPP_API)

# If there is OpenSSL, add OpenSSL source and add OpenSSL liberary
IF(ENABLE_TESTS_OPENSSL_API)
    SET(EXTRA_SOURCES ${EXTRA_SOURCES} base/openssl_cipher.cc base/openssl_cipher_aead.cc)
ENDIF(ENABLE_TESTS_OPENSSL_API)

# Function to dynamically generate compilation of each test cases
FUNCTION(KAT_CIPHER MOD)
    set(TEST_EXE test_${MOD}_kat)
    set(TEST_DATA_FILE dataset_${MOD}.csv)
    ADD_EXECUTABLE(${TEST_EXE} ${TEST_EXE}.cc ${ALC_BASE_FILES} ${EXTRA_SOURCES})
    # Depending on the person, they are gonna run from root dir or binary directory
    # Link dataset to the root dir
    LINK_IF_EXISTS(${CMAKE_CURRENT_SOURCE_DIR}/test_data/${TEST_DATA_FILE} ${CMAKE_BINARY_DIR}/${TEST_DATA_FILE} SYMBOLIC)
    # Link dataset to the actual place of test binary
    LINK_IF_EXISTS(${CMAKE_CURRENT_SOURCE_DIR}/test_data/${TEST_DATA_FILE} ${CMAKE_CURRENT_BINARY_DIR}/${TEST_DATA_FILE} SYMBOLIC)
    TARGET_INCLUDE_DIRECTORIES(${TEST_EXE} PRIVATE ${ALCP_INCLUDES} ${EXTRA_INCLUDES})
    TARGET_COMPILE_OPTIONS(${TEST_EXE} PUBLIC ${ALCP_WARNINGS})
    TARGET_LINK_LIBRARIES(${TEST_EXE} ${LIBS})
    alcp_add_integration_tests_cipher(${TEST_EXE} ${TEST_EXE} ${MOD})
    # Due to known issues, skipping tests with valgrind
    # for more details refer https://ontrack-internal.amd.com/browse/CPUPL-4109
    IF(ALCP_MEMCHECK_VALGRIND)
        message(WARNING "Due to known issues, skipping cipher tests with valgrind")
        #alcp_add_valgrind_check_test(${TEST_EXE} ${CMAKE_BINARY_DIR}/tests/cipher/${TEST_EXE})
    ENDIF()
ENDFUNCTION()

FUNCTION(CROSS_CIPHER MOD)
    set(TEST_EXE test_${MOD}_cross)
    ADD_EXECUTABLE(${TEST_EXE} ${TEST_EXE}.cc ${ALC_BASE_FILES} ${EXTRA_SOURCES})
    TARGET_INCLUDE_DIRECTORIES(${TEST_EXE} PRIVATE ${ALCP_INCLUDES} ${EXTRA_INCLUDES})
    TARGET_COMPILE_OPTIONS(${TEST_EXE} PUBLIC ${ALCP_WARNINGS})
    TARGET_LINK_LIBRARIES(${TEST_EXE} ${LIBS})
    alcp_add_integration_tests_cipher(${TEST_EXE} ${TEST_EXE} ${MOD})
    # Due to known issues, skipping tests with valgrind
    # for more details refer https://ontrack-internal.amd.com/browse/CPUPL-4109
    IF(ALCP_MEMCHECK_VALGRIND)
        message(WARNING "Due to known issues, skipping cipher tests with valgrind")
        #alcp_add_valgrind_check_test(${TEST_EXE} ${CMAKE_BINARY_DIR}/tests/cipher/${TEST_EXE})
    ENDIF()
ENDFUNCTION()

KAT_CIPHER(cbc)
KAT_CIPHER(cfb)
KAT_CIPHER(ctr)
KAT_CIPHER(ofb)
KAT_CIPHER(gcm)
KAT_CIPHER(xts)
KAT_CIPHER(ccm)
KAT_CIPHER(siv)
KAT_CIPHER(chacha20-poly1305)
KAT_CIPHER(chacha20)

CROSS_CIPHER(cbc)
CROSS_CIPHER(cfb)
CROSS_CIPHER(ctr)
CROSS_CIPHER(ofb)
CROSS_CIPHER(gcm)
CROSS_CIPHER(xts)
CROSS_CIPHER(ccm)
CROSS_CIPHER(siv)
CROSS_CIPHER(chacha20)
CROSS_CIPHER(chacha20-poly1305)
