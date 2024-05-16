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


include(${CMAKE_SOURCE_DIR}/cmake/IntegrationTests.cmake)

SET(LIBS ${LIBS} gtest alcp)

 SET(EXTRA_INCLUDES "")

IF(ENABLE_TESTS_IPP_API)
ADD_COMPILE_OPTIONS("-DUSE_IPP")

IF(IPP_INSTALL_DIR)
    MESSAGE(STATUS "IPP_INSTALL_DIR set, overriding fetch path")
ELSE(IPP_INSTALL_DIR)
    SET(IPP_INSTALL_DIR "${CMAKE_SOURCE_DIR}/external")
    MESSAGE(STATUS "IPP_INSTALL_DIR not set, defaulting to external")
ENDIF(IPP_INSTALL_DIR)


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

add_openssl()

 SET(ALCP_INCLUDES
    "${CMAKE_SOURCE_DIR}/include"
    "${CMAKE_SOURCE_DIR}/lib/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/common/include"
    ${EXTRA_INCLUDES}
)

ADD_SUBDIRECTORY(cipher)
ADD_SUBDIRECTORY(digest)
ADD_SUBDIRECTORY(hmac)
ADD_SUBDIRECTORY(ecdh)
ADD_SUBDIRECTORY(cmac)
ADD_SUBDIRECTORY(poly1305)
ADD_SUBDIRECTORY(examples)
ADD_SUBDIRECTORY(rsa)
ADD_SUBDIRECTORY(cipher_experimental)

# FUZZ Testing is enabled only for Clang
if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    ADD_SUBDIRECTORY(Fuzz)
else()
    message("Skipping compilation of Fuzz Tests as LibFuzzer is NOT supported for non-Clang compilers \n")
endif()

# FIXME: Enable this once this test is up and running on windows
IF(UNIX)
    ADD_SUBDIRECTORY(dl_load)
ENDIF(UNIX)