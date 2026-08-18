 # Copyright (C) 2022-2026, Advanced Micro Devices. All rights reserved.
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


include(${ALCP_ROOT}/cmake/IntegrationTests.cmake)
Include(${ALCP_ROOT}/cmake/AlcpTestUtils.cmake)

# Integration tests link the same ALCP variant as applications. Skip gates use
# exported alcp::utils::CpuId methods documented in lib/include/alcp/utils/cpuid.hh.
IF(ALCP_BUILD_SHARED)
    SET(LIBS ${LIBS} gtest alcp)
ELSE()
    SET(LIBS ${LIBS} gtest alcp_static)
ENDIF()

 SET(EXTRA_INCLUDES "")

IF(ENABLE_TESTS_IPP_API)
ADD_COMPILE_OPTIONS("-DUSE_IPP")

IF(IPP_INSTALL_DIR)
    MESSAGE(STATUS "IPP_INSTALL_DIR set, overriding fetch path")
ELSE(IPP_INSTALL_DIR)
    SET(IPP_INSTALL_DIR "${ALCP_ROOT}/external")
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

alcp_add_sanitize_workaround_flags()

SET(ALCP_INCLUDES
    "${ALCP_ROOT}/include"
    "${ALCP_ROOT}/lib/include"
    "${ALCP_BINARY_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/common/include"
    ${EXTRA_INCLUDES}
)

IF(ALCP_EXPORT_TESTS_ONLY)
    IF(ALCP_BUILD_SHARED)
        ADD_SUBDIRECTORY(export)
    ENDIF()
    RETURN()
ENDIF()

ADD_SUBDIRECTORY(cipher)
ADD_SUBDIRECTORY(digest)
ADD_SUBDIRECTORY(hmac)
ADD_SUBDIRECTORY(ecdh)
ADD_SUBDIRECTORY(cmac)
ADD_SUBDIRECTORY(poly1305)
ADD_SUBDIRECTORY(examples)
ADD_SUBDIRECTORY(rsa)
ADD_SUBDIRECTORY(cipher_experimental)
ADD_SUBDIRECTORY(misc)

# FUZZ Testing is enabled only for Clang
if(ALCP_ENABLE_FUZZ_TESTS)
    if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND UNIX)
        ADD_SUBDIRECTORY(Fuzz)
    else()
        message("Skipping compilation of Fuzz Tests as LibFuzzer is NOT supported with non-Clang compilers \n")
    endif()
endif(ALCP_ENABLE_FUZZ_TESTS)

# dl_load test dlopen()s libalcp.so at runtime so it only runs when the
# shared library is being built.
IF(UNIX AND ALCP_BUILD_SHARED)
   ADD_SUBDIRECTORY(dl_load)
ENDIF()

IF(ALCP_BUILD_SHARED)
   ADD_SUBDIRECTORY(export)
ENDIF()
