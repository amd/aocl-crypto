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

# Added aocl-compat as a seperate library
ADD_SUBDIRECTORY(cipher)
ADD_SUBDIRECTORY(asymcipher)
ADD_SUBDIRECTORY(digest)
ADD_SUBDIRECTORY(rng)
ADD_SUBDIRECTORY(mac)
ADD_SUBDIRECTORY(keymgmt)
ADD_SUBDIRECTORY(provider)

# MESSAGE(STATUS "PROVIDER_SOURCES:${PROVIDER_SRC}")

ADD_LIBRARY(openssl-compat 
	${PROVIDER_SRC}
	)
IF(ALCP_COMPAT_ENABLE_OPENSSL_DIGEST)
	SET_SOURCE_FILES_PROPERTIES(provider/alcp_provider.c PROPERTIES COMPILE_FLAGS "-DDIGEST_PROVIDER_ENABLED")
ENDIF(ALCP_COMPAT_ENABLE_OPENSSL_DIGEST)

# Include ALCP header files
TARGET_INCLUDE_DIRECTORIES(openssl-compat PRIVATE ${PROJECT_SOURCE_DIR}/include)
TARGET_INCLUDE_DIRECTORIES(openssl-compat PRIVATE include)

# Link to ALCP shared object file
TARGET_LINK_LIBRARIES(openssl-compat PUBLIC alcp)

# OPENSSL files
IF(WIN32)
	IF(OPENSSL_INSTALL_DIR)
		TARGET_COMPILE_OPTIONS(openssl-compat PRIVATE -Wno-language-extension-token -Wno-missing-field-initializers)
	ENDIF()
ENDIF(WIN32)


