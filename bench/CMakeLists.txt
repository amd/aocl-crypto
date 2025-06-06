 # Copyright (C) 2022-2025, Advanced Micro Devices. All rights reserved.
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

 SET(LIBS ${LIBS} benchmark alcp)
 SET(EXTRA_INCLUDES "")

 IF(ENABLE_TESTS_IPP_API)
     ADD_COMPILE_OPTIONS("-DUSE_IPP")
     IF (NOT IS_DIRECTORY ${IPP_INSTALL_DIR})
        MESSAGE(FATAL_ERROR "IPPCP installation not found!, please export IPP_INSTALL_DIR=<your path to ippcp installation> and retry")
     ENDIF()

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
             SET(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel64/ippcp.lib)
         ELSEIF(EXISTS ${IPP_INSTALL_DIR}/lib/intel/ippcp.lib)
             SET(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel/ippcp.lib)
         ELSE(EXISTS ${IPP_INSTALL_DIR}/lib/ippcp.lib)
             SET(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/ippcp.lib)
         ENDIF()
     ENDIF(WIN32)
     SET(EXTRA_INCLUDES ${EXTRA_INCLUDES} ${IPP_INSTALL_DIR}/include)
 ENDIF(ENABLE_TESTS_IPP_API)

 add_openssl()

set(BENCHMARK_ENABLE_GTEST_TESTS OFF)
set(BENCHMARK_ENABLE_TESTING OFF)
set(BENCHMARK_USE_BUNDLED_GTEST OFF)
ADD_SUBDIRECTORY(digest)
ADD_SUBDIRECTORY(cipher)
ADD_SUBDIRECTORY(cipher_experimental)
ADD_SUBDIRECTORY(hmac)
ADD_SUBDIRECTORY(cmac)
ADD_SUBDIRECTORY(poly1305)
ADD_SUBDIRECTORY(ecdh)
ADD_SUBDIRECTORY(rsa)

