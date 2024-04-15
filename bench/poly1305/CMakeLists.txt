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

INCLUDE(${CMAKE_SOURCE_DIR}/cmake/Benchmarks.cmake)

FILE(GLOB ALC_COMMON_SRC ${CMAKE_SOURCE_DIR}/tests/common/base/*.cc)
SET(ALC_BASE_FILES ${ALC_BASE_FILES} ${ALC_COMMON_SRC} ../../tests/poly1305/base/alc_poly1305.cc ../../tests/poly1305/base/poly1305.cc)
SET(LIBS ${LIBS} benchmark alcp)
SET(EXTRA_INCLUDES "")

IF(ENABLE_TESTS_OPENSSL_API)
    # If there is OpenSSL, add OpenSSL source and add OpenSSL liberary
    SET(EXTRA_SOURCES ${EXTRA_SOURCES} ../../tests/poly1305/base/openssl_poly1305.cc)
ENDIF(ENABLE_TESTS_OPENSSL_API)

ADD_EXECUTABLE(bench_poly1305 bench_poly1305.cc ${ALC_BASE_FILES} ${EXTRA_SOURCES})

TARGET_INCLUDE_DIRECTORIES(bench_poly1305 PRIVATE
    "${CMAKE_SOURCE_DIR}/include"
    "${CMAKE_SOURCE_DIR}/lib/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_SOURCE_DIR}/tests/include"
    "${CMAKE_SOURCE_DIR}/tests/common/include"
    ${EXTRA_INCLUDES})

TARGET_COMPILE_OPTIONS(bench_poly1305 PUBLIC ${ALCP_WARNINGS})
TARGET_LINK_LIBRARIES(bench_poly1305 ${LIBS})
