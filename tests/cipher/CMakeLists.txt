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

INCLUDE(FetchContent)
INCLUDE(GoogleTest)
FetchContent_Declare(gtest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG release-1.12.1)
FetchContent_MakeAvailable(gtest)

if (POLICY CMP0079) # Visibility
  cmake_policy(SET CMP0079 NEW)
endif (POLICY CMP0079)

# Basic sources and libs needed for ALCP
FILE(GLOB ALC_COMMON_SRC ${CMAKE_SOURCE_DIR}/tests/common/base/*.cc)
SET(ALC_BASE_FILES ${ALC_BASE_FILES} 
                   ${ALC_COMMON_SRC} 
                   ${CMAKE_SOURCE_DIR}/tests/cipher/base/alc_cipher.cc 
                   ${CMAKE_SOURCE_DIR}/tests/cipher/base/alc_cipher_aead.cc 
                   ${CMAKE_SOURCE_DIR}/tests/cipher/base/cipher.cc)
SET(LIBS ${LIBS} gtest alcp)

IF(WIN32)
target_link_libraries(gmock PUBLIC gtest)
target_link_libraries(gmock_main PUBLIC gtest_main)
ENDIF()

SET(EXTRA_INCLUDES "")

# sources for tests
SET(ALCP_INCLUDES
    "${CMAKE_SOURCE_DIR}/include"
    "${CMAKE_SOURCE_DIR}/lib/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../common/include"
    ${EXTRA_INCLUDES}
)

IF(ENABLE_TESTS_IPP_API)
    ADD_COMPILE_OPTIONS("-DUSE_IPP")

    IF(IPP_INSTALL_DIR)
        MESSAGE(STATUS "IPP_INSTALL_DIR set, overriding fetch path")
    ELSE(IPP_INSTALL_DIR)
        SET(IPP_INSTALL_DIR "${CMAKE_SOURCE_DIR}/external")
        MESSAGE(STATUS "IPP_INSTALL_DIR not set, defaulting to external")
    ENDIF(IPP_INSTALL_DIR)

    # If there is IPP, add IPP source and add IPP liberary
    SET(EXTRA_SOURCES ${EXTRA_SOURCES} 
                      base/ipp_cipher.cc
                      base/ipp_cipher_aead.cc)
	IF(UNIX)
		IF(EXISTS ${IPP_INSTALL_DIR}/lib/intel64/libippcp.so)
			SET(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel64/libippcp.so)
		ELSE(EXISTS ${IPP_INSTALL_DIR}/lib/intel/libippcp.so)
			SET(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel/libippcp.so)
		ENDIF(EXISTS ${IPP_INSTALL_DIR}/lib/intel64/libippcp.so)
	ENDIF(UNIX)
	IF(WIN32)
	 IF(EXISTS ${IPP_INSTALL_DIR}/lib/intel64/ippcp.lib)
        set(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel64/ippcp.lib)
	 ELSEIF(EXISTS ${IPP_INSTALL_DIR}/lib/intel/ippcp.lib)
        set(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel/ippcp.lib)
	 ELSE(EXISTS ${IPP_INSTALL_DIR}/lib/ippcp.lib)
		set(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/ippcp.lib)
	 ENDIF()
	ENDIF(WIN32)
    SET(EXTRA_INCLUDES ${EXTRA_INCLUDES} ${IPP_INSTALL_DIR}/include)
ENDIF(ENABLE_TESTS_IPP_API)

IF(ENABLE_TESTS_OPENSSL_API)
    ADD_COMPILE_OPTIONS("-DUSE_OSSL")

    IF(OPENSSL_INSTALL_DIR)
        MESSAGE(STATUS "OPENSSL_INSTALL_DIR set, overriding fetch path")
    ELSE(OPENSSL_INSTALL_DIR)
        SET(OPENSSL_INSTALL_DIR "${CMAKE_SOURCE_DIR}/external")
        MESSAGE(STATUS "OPENSSL_INSTALL_DIR not set, defaulting to external")
    ENDIF(OPENSSL_INSTALL_DIR)

    # If there is OpenSSL, add OpenSSL source and add OpenSSL liberary
    SET(EXTRA_SOURCES ${EXTRA_SOURCES}
                      base/openssl_cipher.cc
                      base/openssl_cipher_aead.cc)
	IF(UNIX)
		IF(EXISTS ${OPENSSL_INSTALL_DIR}/lib64/libcrypto.so)
			SET(LIBS ${LIBS} ${OPENSSL_INSTALL_DIR}/lib64/libcrypto.so)
		ELSEIF(EXISTS ${OPENSSL_INSTALL_DIR}/lib/libcrypto.so)
			SET(LIBS ${LIBS} ${OPENSSL_INSTALL_DIR}/lib/libcrypto.so)
		ELSE()
			SET(LIBS ${LIBS} ${OPENSSL_INSTALL_DIR}/lib/x86_64-linux-gnu/libcrypto.so)
		ENDIF()
	ENDIF(UNIX)
	IF(WIN32)
		IF(EXISTS ${OPENSSL_INSTALL_DIR}/lib/libcrypto.lib)
			INCLUDE_DIRECTORIES(${OPENSSL_INSTALL_DIR}/include)
			INCLUDE_DIRECTORIES(${OPENSSL_INSTALL_DIR}/bin)
			SET(LIBS ${LIBS} ${OPENSSL_INSTALL_DIR}/lib/libcrypto.lib)
		ENDIF()
	ENDIF(WIN32)
    SET(EXTRA_INCLUDES ${EXTRA_INCLUDES} ${OPENSSL_INSTALL_DIR}/include)
ENDIF(ENABLE_TESTS_OPENSSL_API)

IF(UNIX)
SET(LIBS ${LIBS} pthread)
ENDIF()


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
    gtest_add_tests(TARGET aes_${MOD}_kat
        TEST_SUFFIX .${MOD})
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
    gtest_add_tests(TARGET chacha20_kat
        TEST_SUFFIX .chacha20)
ENDFUNCTION()

FUNCTION(CROSS_AES MOD)
    ADD_EXECUTABLE(aes_${MOD}_cross test_${MOD}_cross.cc ${ALC_BASE_FILES} ${EXTRA_SOURCES})
    TARGET_INCLUDE_DIRECTORIES(aes_${MOD}_cross PRIVATE
        ${ALCP_INCLUDES}
        ${EXTRA_INCLUDES})
    TARGET_COMPILE_OPTIONS(aes_${MOD}_cross PUBLIC -O2 ${ALCP_WARNINGS})
    TARGET_LINK_LIBRARIES(aes_${MOD}_cross ${LIBS})

    IF(ENABLE_TESTS_OPENSSL_API)
        gtest_add_tests(TARGET aes_${MOD}_cross
            TEST_SUFFIX .${MOD})
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
        gtest_add_tests(TARGET chacha20_cross
            TEST_SUFFIX .chacha20)
    ENDIF(ENABLE_TESTS_OPENSSL_API)
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