 # Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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


FILE(GLOB ZEN4_GCM_SRCS "*.cc")


# clang compiler generates optimal code compared to gcc.
# FIXME! avoid duplication below. Issue for clang > 18
if(ALCP_ENABLE_DYNAMIC_COMPILER_PICK)
	if(CMAKE_COMPILER_IS_GCC)
		find_program(CLANG14 clang-14)
		find_program(CLANG15 clang-15)
		find_program(CLANG16 clang-16)
		find_program(CLANG17 clang-17)
		find_program(CLANG18 clang-18)
 		#below order preference can be modified based on results.
		if (CLANG14)
			set(CMAKE_C_COMPILER "clang-14")
			set(CMAKE_CXX_COMPILER "clang++-14")
			message(STATUS  "clang-14 has been chosen for gcm-zen4 for better performance")
		elseif (CLANG15)
			set(CMAKE_C_COMPILER "clang-15")
			set(CMAKE_CXX_COMPILER "clang++-15")
			message(STATUS  "clang-15 has been chosen for gcm-zen4 for better performance")
		elseif (CLANG16)
			set(CMAKE_C_COMPILER "clang-16")
			set(CMAKE_CXX_COMPILER "clang++-16")
			message(STATUS  "clang-16 has been chosen for gcm-zen4 for better performance")
		elseif (CLANG17)
			set(CMAKE_C_COMPILER "clang-17")
			set(CMAKE_CXX_COMPILER "clang++-17")
			message(STATUS  "clang-17 has been chosen for gcm-zen4 for better performance")
		elseif (CLANG18)
			set(CMAKE_C_COMPILER "clang-18")
			set(CMAKE_CXX_COMPILER "clang++-18")
			message(STATUS  "clang-18 has been chosen for gcm-zen4 for better performance")
		else()
			message(STATUS  "Installing clang compiler (ver >= 14) will help better performance for GCM on zen4 arch over gcc compiler")
	endif()
	endif(CMAKE_COMPILER_IS_GCC)
endif(ALCP_ENABLE_DYNAMIC_COMPILER_PICK)

alcp_get_arch_cflags_zen4_clang()



MESSAGE(STATUS "COMPILE_FLAGS:ZEN4:${ARCH_COMPILE_FLAGS}")


INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/lib/include ../)
INCLUDE_DIRECTORIES(../)

ADD_LIBRARY(arch_zen4_gcm
	OBJECT
	${ZEN4_GCM_SRCS})

TARGET_COMPILE_OPTIONS(arch_zen4_gcm PRIVATE ${ARCH_COMPILE_FLAGS})


# BUG in GCC-12
if(CMAKE_COMPILER_IS_GCC)
if(CMAKE_COMPILER_GCC_VERSION MATCHES "12")
 	MESSAGE(WARNING "GCC12 AVX512 Bug: Using -Wno-maybe-uninitialized -Wno-uninitialized for ZEN4")
	TARGET_COMPILE_OPTIONS(arch_zen4_gcm PRIVATE "-Wno-maybe-uninitialized" "-Wno-uninitialized")
endif(CMAKE_COMPILER_GCC_VERSION MATCHES "12")
endif(CMAKE_COMPILER_IS_GCC)

TARGET_LINK_LIBRARIES(alcp PRIVATE arch_zen4_gcm)
TARGET_LINK_LIBRARIES(alcp_static PRIVATE arch_zen4_gcm)