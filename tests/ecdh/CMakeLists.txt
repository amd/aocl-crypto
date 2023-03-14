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

# Basic sources and libs needed for ALCP
SET(ALC_BASE_FILES ${ALC_BASE_FILES} ../common/base/rng_base.cc ../common/base/base_common.cc base/alc_ecdh_base.cc base/ecdh_base.cc)
SET(LIBS ${LIBS} gtest alcp)

# add this if asan is used
if (ALCP_USE_ASAN)
    SET(LIBS ${LIBS} asan)
endif()

SET(EXTRA_INCLUDES "")

# IF(ENABLE_TESTS_IPP_API)
#     ADD_COMPILE_OPTIONS("-DUSE_IPP")

#     IF(IPP_INSTALL_DIR)
#         MESSAGE(STATUS "IPP_INSTALL_DIR set, overriding fetch path")
#     ELSE(IPP_INSTALL_DIR)
#         SET(IPP_INSTALL_DIR "${CMAKE_SOURCE_DIR}/external")
#         MESSAGE(STATUS "IPP_INSTALL_DIR not set, defaulting to external")
#     ENDIF(IPP_INSTALL_DIR)

#     # If there is IPP, add IPP source and add IPP liberary
#     SET(EXTRA_SOURCES ${EXTRA_SOURCES} base/ipp_digest.cc)
# 	IF(UNIX)
# 		IF(EXISTS ${IPP_INSTALL_DIR}/lib/intel64/libippcp.so)
# 			SET(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel64/libippcp.so)
# 		ELSE(EXISTS ${IPP_INSTALL_DIR}/lib/intel/libippcp.so)
# 			SET(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel/libippcp.so)
# 		ENDIF(EXISTS ${IPP_INSTALL_DIR}/lib/intel64/libippcp.so)
# 	ENDIF(UNIX)
# 	IF(WIN32)
# 	 IF(EXISTS ${IPP_INSTALL_DIR}/lib/intel64/ippcp.lib)
#         set(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel64/ippcp.lib)
# 	 ELSEIF(EXISTS ${IPP_INSTALL_DIR}/lib/intel/ippcp.lib)
#         set(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel/ippcp.lib)
# 	 ELSE(EXISTS ${IPP_INSTALL_DIR}/lib/ippcp.lib)
# 		set(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/ippcp.lib)
# 	 ENDIF()
# 	ENDIF(WIN32)
#     SET(EXTRA_INCLUDES ${EXTRA_INCLUDES} ${IPP_INSTALL_DIR}/include)
# ENDIF(ENABLE_TESTS_IPP_API)

IF(ENABLE_TESTS_OPENSSL_API)
    ADD_COMPILE_OPTIONS("-DUSE_OSSL")

    IF(OPENSSL_INSTALL_DIR)
        MESSAGE(STATUS "OPENSSL_INSTALL_DIR set, overriding fetch path")
    ELSE(OPENSSL_INSTALL_DIR)
        SET(OPENSSL_INSTALL_DIR "${CMAKE_SOURCE_DIR}/external")
        MESSAGE(STATUS "OPENSSL_INSTALL_DIR not set, defaulting to external")
    ENDIF(OPENSSL_INSTALL_DIR)

    # If there is OpenSSL, add OpenSSL source and add OpenSSL library
    SET(EXTRA_SOURCES ${EXTRA_SOURCES} base/openssl_ecdh_base.cc)
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
ENDIF(ENABLE_TESTS_OPENSSL_API)

IF(UNIX)
SET(LIBS ${LIBS} pthread)
ENDIF()

ADD_EXECUTABLE(test_ecdh test_ecdh_kat.cc ${ALC_BASE_FILES} ${EXTRA_SOURCES})

TARGET_INCLUDE_DIRECTORIES(test_ecdh PRIVATE
	"${CMAKE_SOURCE_DIR}/include" 
	"${CMAKE_SOURCE_DIR}/lib/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../common/include"
    ${EXTRA_INCLUDES})

TARGET_COMPILE_OPTIONS(test_ecdh PUBLIC ${ALCP_WARNINGS})
TARGET_LINK_LIBRARIES(test_ecdh ${LIBS})

ADD_EXECUTABLE(test_ecdh_cross test_ecdh_cross.cc ${ALC_BASE_FILES} ${EXTRA_SOURCES})

TARGET_INCLUDE_DIRECTORIES(test_ecdh_cross PRIVATE
	"${CMAKE_SOURCE_DIR}/include"
	"${CMAKE_SOURCE_DIR}/lib/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../common/include"
    ${EXTRA_INCLUDES})

TARGET_COMPILE_OPTIONS(test_ecdh_cross PUBLIC ${ALCP_WARNINGS})
TARGET_LINK_LIBRARIES(test_ecdh_cross ${LIBS})

FUNCTION(TEST_DATA_LINK SHA_ALG)
    # Link dataset to the root dir
    FILE(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/test_data/dataset_${SHA_ALG}.csv ${CMAKE_BINARY_DIR}/dataset_${SHA_ALG}.csv SYMBOLIC)

    # Link dataset to the actual place of test binary
    FILE(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/test_data/dataset_${SHA_ALG}.csv ${CMAKE_CURRENT_BINARY_DIR}/dataset_${SHA_ALG}.csv SYMBOLIC)
ENDFUNCTION(TEST_DATA_LINK SHA_ALG)

# TODO: Fix this name based on curve
TEST_DATA_LINK(ECDH)

gtest_add_tests(TARGET test_ecdh)

IF(ENABLE_TESTS_OPENSSL_API)
    gtest_add_tests(TARGET test_ecdh_cross)
ENDIF(ENABLE_TESTS_OPENSSL_API)
