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
 

SET_DIRECTORY_PROPERTIES(PROPERTIES COMPILE_DEFINITIONS SHOW_MESSAGE=1)
ADD_SUBDIRECTORY(avx2) # Basic Algorithm works on every arch
ADD_SUBDIRECTORY(zen)  # ZEN1/ZEN2 specific, code needs to be optimized for basic ZEN
ADD_SUBDIRECTORY(zen3) # ZEN3 specific, code needs to be optimized for ZEN3 arch
ADD_SUBDIRECTORY(zen4) # ZEN4 specific, code needs to be optimized for ZEN4 arch

#CMAKE_POLICY(SET CMP0079 NEW)

#SET(ARCH_COMMON_SRCS 
#	arch.cc)

SET(ARCH_SRCS ${ARCH_COMMON_SRCS} ${ZEN3_SRCS})

IF ("${ARCH_SRCS}")
TARGET_SOURCES(alcp
	PRIVATE
		${ARCH_SRCS}
	)
ENDIF()

IF (WIN32)
TARGET_LINK_LIBRARIES(alcp
	PRIVATE
	alcp_static)
ENDIF()

#SET(ARCH_SRCS ${ARCH_SRCS} PARENT_SCOPE)
#TARGET_LINK_LIBRARIES(alcp
#	PRIVATE
#	arch_zen3)

MESSAGE(STATUS "Arch common srcs" ${ARCH_SRCS})

