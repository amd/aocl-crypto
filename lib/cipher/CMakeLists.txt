 # Copyright (C) 2021-2024, Advanced Micro Devices. All rights reserved.
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
 

FILE(GLOB CIPHER_SRCS "*.cc")

# Cipher Multi-Update flags
OPTION(ALCP_ENABLE_CCM_MULTI_UPDATE "ENABLE SUPPORT FOR MULTIPLE ENCRYPT/DECRYPT WITH AES CCM" OFF)
OPTION(ALCP_ENABLE_CIPHER_MULTI_UPDATE "ENABLE SUPPORT FOR MULTIPLE ENCRYPT/DECRYPT WITH AES" OFF)
OPTION(ALCP_ENABLE_OFB_MULTI_UPDATE "ENABLE SUPPORT FOR MULTIPLE ENCRYPT/DECRYPT WITH AES OFB" OFF)

# set the options so they are available to the parent scope
set(ALCP_ENABLE_CCM_MULTI_UPDATE ${ALCP_ENABLE_CCM_MULTI_UPDATE} PARENT_SCOPE)
set(ALCP_ENABLE_CIPHER_MULTI_UPDATE ${ALCP_ENABLE_CIPHER_MULTI_UPDATE} PARENT_SCOPE)
set(ALCP_ENABLE_OFB_MULTI_UPDATE ${ALCP_ENABLE_OFB_MULTI_UPDATE} PARENT_SCOPE)

TARGET_SOURCES(alcp
	PRIVATE
		${CIPHER_SRCS}
	)

TARGET_SOURCES(alcp_static
	PRIVATE
		${CIPHER_SRCS}
	)


# FIXME: due to a known failure from valgrind + AOCL Utils' cpuid checks, disabling cipher unit tests with valgrind
# for more details, refer to https://ontrack-internal.amd.com/browse/CPUPL-4109
if(NOT ALCP_MEMCHECK_VALGRIND)
	ADD_SUBDIRECTORY(tests)
endif()