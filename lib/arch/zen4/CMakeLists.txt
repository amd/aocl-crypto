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


FILE(GLOB ZEN4_SRCS "*.cc")

alcp_get_arch_cflags_zen4()

#CMAKE_POLICY(SET CMP0079 NEW)

MESSAGE(STATUS "COMPILE_FLAGS:ZEN4:${ARCH_COMPILE_FLAGS}")
ADD_COMPILE_OPTIONS( ${ARCH_COMPILE_FLAGS})


#Adding -funroll-loops only to sha2_512_avx512.cc file in this arch since it improves performance for digest.
# This flag may improve or decrease performance. But for current implementation in file, it improves performance. 
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
	set_source_files_properties(sha2_512_avx512.cc PROPERTIES COMPILE_FLAGS "-funroll-loops")
endif()

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/lib/include)

ADD_LIBRARY(arch_zen4
	STATIC
	${ZEN4_SRCS})

# BUG in GCC-12
if(CMAKE_COMPILER_IS_GCC)
if(CMAKE_COMPILER_GCC_VERSION MATCHES "12")
 	MESSAGE(WARNING "GCC12 AVX512 Bug: Using -Wno-maybe-uninitialized -Wno-uninitialized for ZEN4")
	TARGET_COMPILE_OPTIONS(arch_zen4 PRIVATE "-Wno-maybe-uninitialized" "-Wno-uninitialized")
endif(CMAKE_COMPILER_GCC_VERSION MATCHES "12")
endif(CMAKE_COMPILER_IS_GCC)

TARGET_LINK_LIBRARIES(alcp PRIVATE arch_zen4)
TARGET_LINK_LIBRARIES(alcp_static PRIVATE arch_zen4)