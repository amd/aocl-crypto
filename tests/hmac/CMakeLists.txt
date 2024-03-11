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
SET(ALC_BASE_FILES ${ALC_BASE_FILES} ${ALC_COMMON_SRC} ../../tests/hmac/base/alc_hmac.cc ../../tests/hmac/base/hmac.cc)

IF(ENABLE_TESTS_IPP_API)
    # If there is IPP, add IPP source and add IPP liberary
    SET(EXTRA_SOURCES ${EXTRA_SOURCES} base/ipp_hmac.cc)
ENDIF(ENABLE_TESTS_IPP_API)

IF(ENABLE_TESTS_OPENSSL_API)
    # If there is OpenSSL, add OpenSSL source and add OpenSSL liberary
    SET(EXTRA_SOURCES ${EXTRA_SOURCES} base/openssl_hmac.cc)
ENDIF(ENABLE_TESTS_OPENSSL_API)

ADD_EXECUTABLE(test_hmac_kat test_hmac_kat.cc ${ALC_BASE_FILES} ${EXTRA_SOURCES})

TARGET_INCLUDE_DIRECTORIES(test_hmac_kat PRIVATE
	${ALCP_INCLUDES}
    ${EXTRA_INCLUDES})

TARGET_COMPILE_OPTIONS(test_hmac_kat PUBLIC ${ALCP_WARNINGS})
TARGET_LINK_LIBRARIES(test_hmac_kat ${LIBS})

ADD_EXECUTABLE(test_hmac_cross test_hmac_cross.cc ${ALC_BASE_FILES} ${EXTRA_SOURCES})

TARGET_INCLUDE_DIRECTORIES(test_hmac_cross PRIVATE
	${ALCP_INCLUDES}
    ${EXTRA_INCLUDES})

TARGET_COMPILE_OPTIONS(test_hmac_cross PUBLIC ${ALCP_WARNINGS})
TARGET_LINK_LIBRARIES(test_hmac_cross ${LIBS})

FUNCTION(TEST_DATA_LINK HMAC_ALG)
    # Link dataset to the root dir
    FILE(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/test_data/dataset_${HMAC_ALG}.csv ${CMAKE_BINARY_DIR}/dataset_${HMAC_ALG}.csv SYMBOLIC)

    # Link dataset to the actual place of test binary
    FILE(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/test_data/dataset_${HMAC_ALG}.csv ${CMAKE_CURRENT_BINARY_DIR}/dataset_${HMAC_ALG}.csv SYMBOLIC)
ENDFUNCTION(TEST_DATA_LINK HMAC_ALG)

TEST_DATA_LINK(HMAC_SHA2_224)
TEST_DATA_LINK(HMAC_SHA2_256)
TEST_DATA_LINK(HMAC_SHA2_384)
TEST_DATA_LINK(HMAC_SHA2_512)

TEST_DATA_LINK(HMAC_SHA3_224)
TEST_DATA_LINK(HMAC_SHA3_256)
TEST_DATA_LINK(HMAC_SHA3_384)
TEST_DATA_LINK(HMAC_SHA3_512)

gtest_add_tests(TARGET test_hmac_kat)

IF(ENABLE_TESTS_OPENSSL_API)
    gtest_add_tests(TARGET test_hmac_cross)
ENDIF(ENABLE_TESTS_OPENSSL_API)

alcp_add_integration_tests("test_hmac_kat" test_hmac_kat)
alcp_add_integration_tests("test_hmac_cross" test_hmac_cross)

IF(ALCP_MEMCHECK_VALGRIND)
    alcp_add_valgrind_check_test("test_hmac_kat" ${CMAKE_BINARY_DIR}/tests/hmac/test_hmac_kat)
    alcp_add_valgrind_check_test("test_hmac_cross" ${CMAKE_BINARY_DIR}/tests/hmac/test_hmac_cross)
ENDIF(ALCP_MEMCHECK_VALGRIND)

