# Copyright (C) 2021-2026, Advanced Micro Devices. All rights reserved.
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
 

FILE(GLOB ZEN3_SRCS "*.cc")

alcp_get_arch_cflags_zen3()

#CMAKE_POLICY(SET CMP0079 NEW)

MESSAGE(STATUS "COMPILE_FLAGS:ZEN3:${ARCH_COMPILE_FLAGS}")
ADD_COMPILE_OPTIONS(${ARCH_COMPILE_FLAGS})

#Adding -funroll-loops only to Sha2_512.cc file in this arch since it improves performance for digest.
# This flag may improve or decrease performance. But for current implementation in file, it improves performance. 
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
	set_source_files_properties(Sha2_512.cc PROPERTIES COMPILE_FLAGS "-funroll-loops")
	# Pre-RA scheduling cut spills in the register-tight Poly1305 multiply loop.
	# On a Zen6 build host, also tune scheduling for znver6 (ISA-safe; Poly1305-only uplift).
	set(POLY1305_FLAGS "-fschedule-insns")
	alcp_detect_host_znver(POLY1305_HOST_ZNVER)
	if(POLY1305_HOST_ZNVER STREQUAL "znver6")
		string(APPEND POLY1305_FLAGS " -mtune=znver6")
	endif()
	set_source_files_properties(poly1305.cc PROPERTIES COMPILE_FLAGS "${POLY1305_FLAGS}")
	set_source_files_properties(x25519.cc PROPERTIES COMPILE_FLAGS "-O2")
endif()

INCLUDE_DIRECTORIES(${ALCP_ROOT}/lib/include)

ADD_LIBRARY(arch_zen3
	OBJECT
	${ZEN3_SRCS})

# FIXME: temporarily suppressing this. Known issue with gcc14
if(CMAKE_COMPILER_IS_GCC AND CMAKE_COMPILER_GCC_VERSION VERSION_GREATER_EQUAL "14")
	MESSAGE(WARNING "GCC${CMAKE_COMPILER_GCC_VERSION}: Disabling array out of bounds checks (-Wno-array-bounds) for zen3 sources")
	TARGET_COMPILE_OPTIONS(arch_zen3 PRIVATE "-Wno-array-bounds")
endif()

IF(ALCP_ENABLE_CIPHER_MULTI_UPDATE)
	TARGET_COMPILE_DEFINITIONS(arch_zen3 PRIVATE "AES_MULTI_UPDATE")	
ENDIF(ALCP_ENABLE_CIPHER_MULTI_UPDATE)

ALCP_TARGET_LINK_LIBRARIES(PRIVATE arch_zen3)
