 # Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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
SET(ALC_BASE_FILES ${ALC_BASE_FILES} ${ALC_COMMON_SRC} ../../tests/poly1305/base/alc_poly1305.cc ../../tests/poly1305/base/poly1305.cc)


IF(ENABLE_TESTS_OPENSSL_API)
    # If there is OpenSSL, add OpenSSL source and add OpenSSL liberary
    SET(EXTRA_SOURCES ${EXTRA_SOURCES} base/openssl_poly1305.cc)
ENDIF(ENABLE_TESTS_OPENSSL_API)


ADD_EXECUTABLE(test_poly1305_kat test_poly1305_kat.cc ${ALC_BASE_FILES} ${EXTRA_SOURCES})

TARGET_INCLUDE_DIRECTORIES(test_poly1305_kat PRIVATE
    ${ALCP_INCLUDES}
    ${EXTRA_INCLUDES})

TARGET_COMPILE_OPTIONS(test_poly1305_kat PUBLIC ${ALCP_WARNINGS})
TARGET_LINK_LIBRARIES(test_poly1305_kat ${LIBS})

ADD_EXECUTABLE(test_poly1305_cross test_poly1305_cross.cc ${ALC_BASE_FILES} ${EXTRA_SOURCES})

TARGET_INCLUDE_DIRECTORIES(test_poly1305_cross PRIVATE
    ${ALCP_INCLUDES}
    ${EXTRA_INCLUDES})

TARGET_COMPILE_OPTIONS(test_poly1305_cross PUBLIC ${ALCP_WARNINGS})
TARGET_LINK_LIBRARIES(test_poly1305_cross ${LIBS})

FUNCTION(TEST_DATA_LINK)
    # Link dataset to the root dir
    FILE(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/test_data/dataset_poly1305.csv ${CMAKE_BINARY_DIR}/dataset_poly1305.csv SYMBOLIC)

    # Link dataset to the actual place of test binary
    FILE(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/test_data/dataset_poly1305.csv ${CMAKE_CURRENT_BINARY_DIR}/dataset_poly1305.csv SYMBOLIC)

ENDFUNCTION(TEST_DATA_LINK)

TEST_DATA_LINK()

gtest_add_tests(TARGET test_poly1305_kat)

IF(ENABLE_TESTS_OPENSSL_API)
    gtest_add_tests(TARGET test_poly1305_cross)
ENDIF(ENABLE_TESTS_OPENSSL_API)
