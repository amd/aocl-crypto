 # Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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


Include(${CMAKE_SOURCE_DIR}/cmake/AlcpTestUtils.cmake)

 # Basic sources and libs needed for ALCP
FILE(GLOB ALC_COMMON_SRC ${CMAKE_SOURCE_DIR}/tests/common/base/*.cc)
SET(ALC_BASE_FILES ${ALC_BASE_FILES} ${ALC_COMMON_SRC} base/alc_rsa.cc)
SET(LIBS ${LIBS} gtest alcp)

IF(ENABLE_TESTS_IPP_API)
    # If there is IPP, add IPP source and add IPP liberary
    SET(EXTRA_SOURCES ${EXTRA_SOURCES} base/ipp_rsa.cc)
ENDIF(ENABLE_TESTS_IPP_API)

IF(ENABLE_TESTS_OPENSSL_API)
    # If there is OpenSSL, add OpenSSL source and add OpenSSL library
    SET(EXTRA_SOURCES ${EXTRA_SOURCES} base/openssl_rsa.cc)
ENDIF(ENABLE_TESTS_OPENSSL_API)

ADD_EXECUTABLE(test_rsa_kat test_rsa_kat.cc ${ALC_BASE_FILES} ${EXTRA_SOURCES})

TARGET_INCLUDE_DIRECTORIES(test_rsa_kat PRIVATE
	${ALCP_INCLUDES}
    ${EXTRA_INCLUDES})

TARGET_COMPILE_OPTIONS(test_rsa_kat PUBLIC ${ALCP_WARNINGS})
TARGET_LINK_LIBRARIES(test_rsa_kat ${LIBS})

ADD_EXECUTABLE(test_rsa_cross test_rsa_cross.cc ${ALC_BASE_FILES} ${EXTRA_SOURCES})

TARGET_INCLUDE_DIRECTORIES(test_rsa_cross PRIVATE
    ${ALCP_INCLUDES}
    ${EXTRA_INCLUDES})

TARGET_COMPILE_OPTIONS(test_rsa_cross PUBLIC ${ALCP_WARNINGS})
TARGET_LINK_LIBRARIES(test_rsa_cross ${LIBS})

FUNCTION(TEST_DATA_LINK RSA_ALG KEY_SIZE PADDING_MODE)
    # Link dataset to the root dir
    LINK_IF_EXISTS(${CMAKE_CURRENT_SOURCE_DIR}/test_data/dataset_RSA_${RSA_ALG}_${KEY_SIZE}_${PADDING_MODE}.csv ${CMAKE_BINARY_DIR}/dataset_RSA_${RSA_ALG}_${KEY_SIZE}_${PADDING_MODE}.csv SYMBOLIC)
    # Link dataset to the actual place of test binary
    LINK_IF_EXISTS(${CMAKE_CURRENT_SOURCE_DIR}/test_data/dataset_RSA_${RSA_ALG}_${KEY_SIZE}_${PADDING_MODE}.csv ${CMAKE_CURRENT_BINARY_DIR}/dataset_RSA_${RSA_ALG}_${KEY_SIZE}_${PADDING_MODE}.csv SYMBOLIC)
ENDFUNCTION(TEST_DATA_LINK RSA_ALG)

TEST_DATA_LINK(EncryptDecrypt 1024 no_padding)
TEST_DATA_LINK(EncryptDecrypt 2048 no_padding)
TEST_DATA_LINK(EncryptDecrypt 1024 OAEP)
TEST_DATA_LINK(EncryptDecrypt 2048 OAEP)

TEST_DATA_LINK(EncryptDecrypt 2048 PKCS)

TEST_DATA_LINK(SignVerify 2048 PSS)
TEST_DATA_LINK(SignVerify 2048 PKCS)

alcp_add_integration_tests("test_rsa_kat" test_rsa_kat)
alcp_add_integration_tests("test_rsa_cross" test_rsa_cross)

IF(ALCP_MEMCHECK_VALGRIND)
    alcp_add_valgrind_check_test("test_rsa_kat" ${CMAKE_BINARY_DIR}/tests/rsa/test_rsa_kat)
    alcp_add_valgrind_check_test("test_rsa_cross" ${CMAKE_BINARY_DIR}/tests/rsa/test_rsa_cross)
ENDIF(ALCP_MEMCHECK_VALGRIND)
