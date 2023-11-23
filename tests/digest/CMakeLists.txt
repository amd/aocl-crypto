 # Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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

# Basic sources and libs needed for ALCP
FILE(GLOB ALC_COMMON_SRC ${CMAKE_SOURCE_DIR}/tests/common/base/*.cc)
SET(ALC_BASE_FILES ${ALC_BASE_FILES} ${ALC_COMMON_SRC} ../../tests/digest/base/alc_digest.cc ../../tests/digest/base/digest.cc)
SET(LIBS ${LIBS} gtest alcp)



IF(ENABLE_TESTS_IPP_API)
    # If there is IPP, add IPP source and add IPP liberary
    SET(EXTRA_SOURCES ${EXTRA_SOURCES} base/ipp_digest.cc)
ENDIF(ENABLE_TESTS_IPP_API)

IF(ENABLE_TESTS_OPENSSL_API)
    # If there is OpenSSL, add OpenSSL source and add OpenSSL liberary
    SET(EXTRA_SOURCES ${EXTRA_SOURCES} base/openssl_digest.cc)
ENDIF(ENABLE_TESTS_OPENSSL_API)

ADD_EXECUTABLE(test_digest_kat test_digest_kat.cc ${ALC_BASE_FILES} ${EXTRA_SOURCES})

TARGET_INCLUDE_DIRECTORIES(test_digest_kat PRIVATE
	${ALCP_INCLUDES}
    ${EXTRA_INCLUDES})

TARGET_COMPILE_OPTIONS(test_digest_kat PUBLIC ${ALCP_WARNINGS})
TARGET_LINK_LIBRARIES(test_digest_kat ${LIBS})

ADD_EXECUTABLE(test_digest_cross test_digest_cross.cc ${ALC_BASE_FILES} ${EXTRA_SOURCES})

TARGET_INCLUDE_DIRECTORIES(test_digest_cross PRIVATE
	${ALCP_INCLUDES}
    ${EXTRA_INCLUDES})

TARGET_COMPILE_OPTIONS(test_digest_cross PUBLIC ${ALCP_WARNINGS})
TARGET_LINK_LIBRARIES(test_digest_cross ${LIBS})

FUNCTION(TEST_DATA_LINK SHA_ALG)
    # Link dataset to the root dir
    FILE(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/test_data/dataset_${SHA_ALG}.csv ${CMAKE_BINARY_DIR}/dataset_${SHA_ALG}.csv SYMBOLIC)

    # Link dataset to the actual place of test binary
    FILE(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/test_data/dataset_${SHA_ALG}.csv ${CMAKE_CURRENT_BINARY_DIR}/dataset_${SHA_ALG}.csv SYMBOLIC)

ENDFUNCTION(TEST_DATA_LINK SHA_ALG)

TEST_DATA_LINK(SHA_224)
TEST_DATA_LINK(SHA_256)
TEST_DATA_LINK(SHA_384)
TEST_DATA_LINK(SHA_512)
TEST_DATA_LINK(SHA3_224)
TEST_DATA_LINK(SHA3_256)
TEST_DATA_LINK(SHA3_384)
TEST_DATA_LINK(SHA3_512)
TEST_DATA_LINK(SHA3_SHAKE_128)
TEST_DATA_LINK(SHA3_SHAKE_256)
TEST_DATA_LINK(SHA_512_224)
TEST_DATA_LINK(SHA_512_256)

gtest_add_tests(TARGET test_digest_kat)

IF(ENABLE_TESTS_OPENSSL_API)
    gtest_add_tests(TARGET test_digest_cross)
ENDIF(ENABLE_TESTS_OPENSSL_API)
