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


FILE(GLOB ALC_COMMON_SRC ${CMAKE_SOURCE_DIR}/tests/common/base/*.cc)
SET(ALC_BASE_FILES ${ALC_BASE_FILES} ${ALC_COMMON_SRC} ../../tests/rsa/base/alc_rsa.cc)


IF(ENABLE_TESTS_IPP_API)
    ADD_COMPILE_OPTIONS("-DUSE_IPP")

    IF(IPP_INSTALL_DIR)
        MESSAGE(STATUS "IPP_INSTALL_DIR set, overriding fetch path")
    ELSE(IPP_INSTALL_DIR)
        SET(IPP_INSTALL_DIR "${CMAKE_SOURCE_DIR}/external")
        MESSAGE(STATUS "IPP_INSTALL_DIR not set, defaulting to external")
    ENDIF(IPP_INSTALL_DIR)

    # If there is IPP, add IPP source and add IPP library
    SET(EXTRA_SOURCES ${EXTRA_SOURCES} ../../tests/rsa/base/ipp_rsa.cc)
	IF(UNIX)

        # for ECC functions
        IF(EXISTS ${IPP_INSTALL_DIR}/lib/intel64/libcrypto_mb.so)
            SET(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel64/libcrypto_mb.so)
        ELSE(EXISTS ${IPP_INSTALL_DIR}/lib/intel/libcrypto_mb.so)
            SET(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel/libcrypto_mb.so)
        ENDIF(EXISTS ${IPP_INSTALL_DIR}/lib/intel64/libcrypto_mb.so)
	ENDIF(UNIX)
	IF(WIN32)

        # for ECC functions
        IF(EXISTS ${IPP_INSTALL_DIR}/lib/intel64/crypto_mb.lib)
            SET(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel64/crypto_mb.lib)
        ELSEIF(EXISTS ${IPP_INSTALL_DIR}/lib/intel/crypto_mb.lib)
            SET(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel/crypto_mb.lib)
        ELSE(EXISTS ${IPP_INSTALL_DIR}/lib/crypto_mb.lib)
            SET(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/crypto_mb.lib)
        ENDIF(EXISTS ${IPP_INSTALL_DIR}/lib/intel64/crypto_mb.lib)
	ENDIF(WIN32)
    SET(EXTRA_INCLUDES ${EXTRA_INCLUDES} ${IPP_INSTALL_DIR}/include)
ENDIF(ENABLE_TESTS_IPP_API)

IF(ENABLE_TESTS_OPENSSL_API)
    # If there is OpenSSL, add OpenSSL source and add OpenSSL liberary
    SET(EXTRA_SOURCES ${EXTRA_SOURCES} ../../tests/rsa/base/openssl_rsa.cc)
ENDIF(ENABLE_TESTS_OPENSSL_API)

ADD_EXECUTABLE(bench_rsa bench_rsa.cc ${ALC_BASE_FILES} ${EXTRA_SOURCES})

TARGET_INCLUDE_DIRECTORIES(bench_rsa PRIVATE
    "${CMAKE_SOURCE_DIR}/include"
    "${CMAKE_SOURCE_DIR}/lib/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_SOURCE_DIR}/tests/include"
    "${CMAKE_SOURCE_DIR}/tests/common/include"
    ${EXTRA_INCLUDES})

TARGET_COMPILE_OPTIONS(bench_rsa PUBLIC ${ALCP_WARNINGS})
TARGET_LINK_LIBRARIES(bench_rsa ${LIBS})
