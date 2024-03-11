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
endif (POLICY CMP0079)

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

IF(ENABLE_TESTS_IPP_API)
    # If there is IPP, add IPP source and add IPP liberary
    SET(EXTRA_SOURCES ${EXTRA_SOURCES}
                      base/ipp_cipher.cc
                      base/ipp_cipher_aead.cc)
ENDIF(ENABLE_TESTS_IPP_API)

IF(ENABLE_TESTS_OPENSSL_API)
    # If there is OpenSSL, add OpenSSL source and add OpenSSL liberary
    SET(EXTRA_SOURCES ${EXTRA_SOURCES}
                      base/openssl_cipher.cc
                      base/openssl_cipher_aead.cc)
ENDIF(ENABLE_TESTS_OPENSSL_API)


# Function to dynamically generate compilation of each test cases
FUNCTION(KAT_AES MOD)
    ADD_EXECUTABLE(aes_${MOD}_kat test_${MOD}_kat.cc ${ALC_BASE_FILES} ${EXTRA_SOURCES})

    # Depending on the person, they are gonna run from root dir or binary directory
    # Link dataset to the root dir
    FILE(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/test_data/dataset_${MOD}.csv ${CMAKE_BINARY_DIR}/dataset_${MOD}.csv SYMBOLIC)

    # Link dataset to the actual place of test binary
    FILE(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/test_data/dataset_${MOD}.csv ${CMAKE_CURRENT_BINARY_DIR}/dataset_${MOD}.csv SYMBOLIC)

    TARGET_INCLUDE_DIRECTORIES(aes_${MOD}_kat PRIVATE
        ${ALCP_INCLUDES}
        ${EXTRA_INCLUDES})

    TARGET_COMPILE_OPTIONS(aes_${MOD}_kat PUBLIC -O2 ${ALCP_WARNINGS})
    TARGET_LINK_LIBRARIES(aes_${MOD}_kat ${LIBS})
    gtest_add_tests(TARGET aes_${MOD}_kat TEST_SUFFIX .${MOD})
ENDFUNCTION()

# Function to dynamically generate compilation of each test cases for chacha20
FUNCTION(KAT_CHACHA20)
    ADD_EXECUTABLE(chacha20_kat test_chacha20_kat.cc ${ALC_BASE_FILES} ${EXTRA_SOURCES})
    # Depending on the person, they are gonna run from root dir or binary directory
    FILE(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/test_data/dataset_chacha20.csv ${CMAKE_BINARY_DIR}/dataset_chacha20.csv SYMBOLIC)
    # Link dataset to the actual place of test binary
    FILE(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/test_data/dataset_chacha20.csv ${CMAKE_CURRENT_BINARY_DIR}/dataset_chacha20.csv SYMBOLIC)

    TARGET_INCLUDE_DIRECTORIES(chacha20_kat PRIVATE
        ${ALCP_INCLUDES}
        ${EXTRA_INCLUDES})

    TARGET_COMPILE_OPTIONS(chacha20_kat PUBLIC -O2 ${ALCP_WARNINGS})
    TARGET_LINK_LIBRARIES(chacha20_kat ${LIBS})
    gtest_add_tests(TARGET chacha20_kat TEST_SUFFIX .chacha20)
    alcp_add_integration_tests("chacha20_kat" chacha20_kat)
    IF(ALCP_MEMCHECK_VALGRIND)
        alcp_add_valgrind_check_test("chacha20_kat" ${CMAKE_BINARY_DIR}/tests/cipher/chacha20_kat)
    ENDIF(ALCP_MEMCHECK_VALGRIND)
ENDFUNCTION()

FUNCTION(CROSS_AES MOD)
    ADD_EXECUTABLE(aes_${MOD}_cross test_${MOD}_cross.cc ${ALC_BASE_FILES} ${EXTRA_SOURCES})
    TARGET_INCLUDE_DIRECTORIES(aes_${MOD}_cross PRIVATE
        ${ALCP_INCLUDES}
        ${EXTRA_INCLUDES})
    TARGET_COMPILE_OPTIONS(aes_${MOD}_cross PUBLIC -O2 ${ALCP_WARNINGS})
    TARGET_LINK_LIBRARIES(aes_${MOD}_cross ${LIBS})

    IF(ENABLE_TESTS_OPENSSL_API)
        gtest_add_tests(TARGET aes_${MOD}_cross TEST_SUFFIX .${MOD})
    ENDIF(ENABLE_TESTS_OPENSSL_API)
ENDFUNCTION()

FUNCTION(CROSS_CHACHA20)
    ADD_EXECUTABLE(chacha20_cross test_chacha20_cross.cc ${ALC_BASE_FILES} ${EXTRA_SOURCES})
    TARGET_INCLUDE_DIRECTORIES(chacha20_cross PRIVATE
        ${ALCP_INCLUDES}
        ${EXTRA_INCLUDES})
    TARGET_COMPILE_OPTIONS(chacha20_cross PUBLIC -O2 ${ALCP_WARNINGS})
    TARGET_LINK_LIBRARIES(chacha20_cross ${LIBS})
    IF(ENABLE_TESTS_OPENSSL_API)
        gtest_add_tests(TARGET chacha20_cross TEST_SUFFIX .chacha20)
    ENDIF(ENABLE_TESTS_OPENSSL_API)
    alcp_add_integration_tests("chacha20_cross" chacha20_cross)
    IF(ALCP_MEMCHECK_VALGRIND)
        alcp_add_valgrind_check_test("chacha20_cross" ${CMAKE_BINARY_DIR}/tests/cipher/chacha20_cross)
    ENDIF(ALCP_MEMCHECK_VALGRIND)
ENDFUNCTION()

KAT_AES(cbc)
KAT_AES(cfb)
KAT_AES(ctr)
KAT_AES(ofb)
KAT_AES(gcm)
KAT_AES(xts)
KAT_AES(ccm)
KAT_AES(siv)

KAT_CHACHA20()
CROSS_CHACHA20()

CROSS_AES(cbc)
CROSS_AES(cfb)
CROSS_AES(ctr)
CROSS_AES(ofb)
CROSS_AES(gcm)
CROSS_AES(xts)
CROSS_AES(ccm)
CROSS_AES(siv)