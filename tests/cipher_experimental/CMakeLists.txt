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

INCLUDE(FetchContent)
INCLUDE(GoogleTest)
FetchContent_Declare(gtest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG release-1.12.1)
FetchContent_MakeAvailable(gtest)

FILE(GLOB COMMON_SRCS ${CMAKE_SOURCE_DIR}/tests/common/base/*.cc)
FILE(GLOB ALC_CIPHER_FWK_SRCS ${CMAKE_SOURCE_DIR}/tests/cipher_experimental/framework/alc_*.cc)
SET(LIBS ${LIBS} gtest alcp)

IF(WIN32)
target_link_libraries(gmock PUBLIC gtest)
target_link_libraries(gmock_main PUBLIC gtest_main)
ENDIF()

SET(EXTRA_SOURCES "")
SET(EXTRA_INCLUDES "")


# Function to dynamically generate compilation of each test cases
FUNCTION(KAT_AES MOD)
    ADD_EXECUTABLE(aes_${MOD}_kat_experimental test_${MOD}_kat.cc ${COMMON_SRCS} ${ALC_CIPHER_FWK_SRCS} ${EXTRA_SOURCES})

    # Below code must be enabled once we merge completely
    # Depending on the person, they are gonna run from root dir or binary directory
    # Link dataset to the root dir
    # FILE(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/dataset/dataset_${MOD}.csv ${CMAKE_BINARY_DIR}/dataset_${MOD}.csv SYMBOLIC)

    # Link dataset to the actual place of test binary
    # FILE(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/dataset/dataset_${MOD}.csv ${CMAKE_CURRENT_BINARY_DIR}/dataset_${MOD}.csv SYMBOLIC)

    TARGET_INCLUDE_DIRECTORIES(aes_${MOD}_kat_experimental PRIVATE
        "${CMAKE_SOURCE_DIR}/include"
        "${CMAKE_SOURCE_DIR}/lib/include"
        "${CMAKE_SOURCE_DIR}/tests/include"
        "${CMAKE_SOURCE_DIR}/tests/common/include"
        ${EXTRA_INCLUDES})

    TARGET_COMPILE_OPTIONS(aes_${MOD}_kat_experimental PUBLIC ${ALCP_WARNINGS})
    TARGET_LINK_LIBRARIES(aes_${MOD}_kat_experimental ${LIBS})
    gtest_add_tests(TARGET aes_${MOD}_kat_experimental
        TEST_SUFFIX .${MOD})
ENDFUNCTION()

KAT_AES(gcm)

