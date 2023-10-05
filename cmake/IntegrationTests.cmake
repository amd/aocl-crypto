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
# SET(COMMON_SRCS ${COMMON_SRCS} PARENT_SCOPE)

SET(LIBS ${LIBS} gtest alcp)

SET(ALCP_TEST_INCLUDES "${CMAKE_SOURCE_DIR}/include"
                       "${CMAKE_SOURCE_DIR}/lib/include"
                       "${CMAKE_SOURCE_DIR}/tests/include"
                       "${CMAKE_SOURCE_DIR}/tests/common/include"
    )

IF(WIN32)
target_link_libraries(gmock PUBLIC gtest)
target_link_libraries(gmock_main PUBLIC gtest_main)
ENDIF()

function(add_openssl OPENSSL_SOURCE_FILES)
    IF(ENABLE_TESTS_OPENSSL_API)
    ADD_COMPILE_OPTIONS("-DUSE_OSSL")

    IF(OPENSSL_INSTALL_DIR)
        MESSAGE(STATUS "OPENSSL_INSTALL_DIR set, overriding fetch path")
    ELSE(OPENSSL_INSTALL_DIR)
        SET(OPENSSL_INSTALL_DIR "${CMAKE_SOURCE_DIR}/external")
        MESSAGE(STATUS "OPENSSL_INSTALL_DIR not set, defaulting to external")
    ENDIF(OPENSSL_INSTALL_DIR)

    # If there is OpenSSL, add OpenSSL source and add OpenSSL liberary
    SET(OPENSSL_SOURCES ${OPENSSL_SOURCE_FILES} PARENT_SCOPE)
    IF(UNIX)
        IF(EXISTS ${OPENSSL_INSTALL_DIR}/lib64/libcrypto.so)
            SET(OPENSSL_LIBS ${OPENSSL_LIBS} ${OPENSSL_INSTALL_DIR}/lib64/libcrypto.so)
        ELSEIF(EXISTS ${OPENSSL_INSTALL_DIR}/lib/libcrypto.so)
            SET(OPENSSL_LIBS ${OPENSSL_LIBS} ${OPENSSL_INSTALL_DIR}/lib/libcrypto.so)
        ELSE()
            SET(OPENSSL_LIBS ${OPENSSL_LIBS} ${OPENSSL_INSTALL_DIR}/lib/x86_64-linux-gnu/libcrypto.so)
        ENDIF()
    ENDIF(UNIX)
    IF(WIN32)
        IF(EXISTS ${OPENSSL_INSTALL_DIR}/lib/libcrypto.lib)
            INCLUDE_DIRECTORIES(${OPENSSL_INSTALL_DIR}/include)
            INCLUDE_DIRECTORIES(${OPENSSL_INSTALL_DIR}/bin)
            SET(OPENSSL_LIBS ${OPENSSL_LIBS} ${OPENSSL_INSTALL_DIR}/lib/libcrypto.lib)
        ENDIF()
    ENDIF(WIN32)
    SET(OPENSSL_INCLUDES ${OPENSSL_INSTALL_DIR}/include PARENT_SCOPE)
    SET(OPENSSL_LIBS ${OPENSSL_LIBS} PARENT_SCOPE)
    ENDIF(ENABLE_TESTS_OPENSSL_API)
endfunction(add_openssl OPENSSL_SOURCE_FILES)

function(add_ipp IPP_SOURCE_FILES)
    IF(ENABLE_TESTS_IPP_API)
        ADD_COMPILE_OPTIONS("-DUSE_IPP")

        IF(IPP_INSTALL_DIR)
            MESSAGE(STATUS "IPP_INSTALL_DIR set, overriding fetch path")
        ELSE(IPP_INSTALL_DIR)
            SET(IPP_INSTALL_DIR "${CMAKE_SOURCE_DIR}/external")
            MESSAGE(STATUS "IPP_INSTALL_DIR not set, defaulting to external")
        ENDIF(IPP_INSTALL_DIR)

        # If there is IPP, add IPP source and add IPP liberary
        SET(IPP_SOURCES ${IPP_SOURCE_FILES} PARENT_SCOPE)
        IF(UNIX)
            IF(EXISTS ${IPP_INSTALL_DIR}/lib/intel64/libippcp.so)
                SET(IPP_LIBS ${IPP_LIBS} ${IPP_INSTALL_DIR}/lib/intel64/libippcp.so)
            ELSE(EXISTS ${IPP_INSTALL_DIR}/lib/intel/libippcp.so)
                SET(IPP_LIBS ${IPP_LIBS} ${IPP_INSTALL_DIR}/lib/intel/libippcp.so)
            ENDIF(EXISTS ${IPP_INSTALL_DIR}/lib/intel64/libippcp.so)
        ENDIF(UNIX)
        IF(WIN32)
        IF(EXISTS ${IPP_INSTALL_DIR}/lib/intel64/ippcp.lib)
            set(IPP_LIBS ${IPP_LIBS} ${IPP_INSTALL_DIR}/lib/intel64/ippcp.lib)
        ELSEIF(EXISTS ${IPP_INSTALL_DIR}/lib/intel/ippcp.lib)
            set(IPP_LIBS ${IPP_LIBS} ${IPP_INSTALL_DIR}/lib/intel/ippcp.lib)
        ELSE(EXISTS ${IPP_INSTALL_DIR}/lib/ippcp.lib)
            set(IPP_LIBS ${IPP_LIBS} ${IPP_INSTALL_DIR}/lib/ippcp.lib)
        ENDIF()
        ENDIF(WIN32)
        SET(IPP_INCLUDES ${IPP_INSTALL_DIR}/include PARENT_SCOPE)
        SET(IPP_LIBS ${IPP_LIBS} PARENT_SCOPE)
    ENDIF(ENABLE_TESTS_IPP_API)
endfunction(add_ipp IPP_SOURCE_FILES)

if (POLICY CMP0079) # Visibility
  cmake_policy(SET CMP0079 NEW)
endif (POLICY CMP0079)

# Function to dynamically generate compilation of each test cases
FUNCTION(AES_TEST TYPE MOD)
    ADD_EXECUTABLE(aes_${MOD}_${TYPE}_experimental test_${MOD}_${TYPE}.cc 
                                                   ${COMMON_SRCS} 
                                                   ${ALC_CIPHER_FWK_SRCS} 
                                                   ${EXTRA_SOURCES} 
                                                   ${OPENSSL_SOURCES}
                                                   ${IPP_SOURCES})
    # Below code must be enabled once we merge completely
    # Depending on the person, they are gonna run from root dir or binary directory
    # Link dataset to the root dir
    # FILE(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/dataset/dataset_${MOD}.csv ${CMAKE_BINARY_DIR}/dataset_${MOD}.csv SYMBOLIC)

    # Link dataset to the actual place of test binary
    # FILE(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/dataset/dataset_${MOD}.csv ${CMAKE_CURRENT_BINARY_DIR}/dataset_${MOD}.csv SYMBOLIC)

    TARGET_INCLUDE_DIRECTORIES(aes_${MOD}_${TYPE}_experimental PRIVATE
        ${ALCP_TEST_INCLUDES}
        ${OPENSSL_INCLUDES}
        ${IPP_INCLUDES})

    TARGET_COMPILE_OPTIONS(aes_${MOD}_${TYPE}_experimental PUBLIC ${ALCP_WARNINGS})
    TARGET_LINK_LIBRARIES(aes_${MOD}_${TYPE}_experimental ${LIBS} 
                                                      ${OPENSSL_LIBS} 
                                                      ${IPP_LIBS})
    gtest_add_tests(TARGET aes_${MOD}_${TYPE}_experimental
        TEST_SUFFIX .${MOD})
ENDFUNCTION()