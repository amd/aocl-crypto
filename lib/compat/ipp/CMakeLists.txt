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
 
# Added aocl-compat as a seperate liberary
FILE(GLOB IPP_SRCS "*.cc" "aes/*.cc" "sha2/*.cc" "common/*.cc" "ec/*.cc" "mac/*.cc")
ADD_LIBRARY(ipp-compat 
	${IPP_SRCS}
	)

# Link to ALCP shared object file
TARGET_LINK_LIBRARIES(ipp-compat PUBLIC alcp)
# Include internal header files
TARGET_INCLUDE_DIRECTORIES(ipp-compat PRIVATE include)

# Include ALCP header files
TARGET_INCLUDE_DIRECTORIES(ipp-compat PRIVATE ${ALCP_ROOT}/include)

# Include IPPCP files
IF(IPP_INSTALL_DIR)
	TARGET_INCLUDE_DIRECTORIES(ipp-compat PRIVATE ${IPP_INSTALL_DIR}/include)
ENDIF(IPP_INSTALL_DIR)

if(CMAKE_COMPILER_IS_GCC)
	# FIXME: Need to investigate this, silencing this warning as IPP Compat library is deprioritized feature
	TARGET_COMPILE_OPTIONS(ipp-compat PRIVATE -Wno-maybe-uninitialized)
    MESSAGE(STATUS "Due to a known issue with gcc, enforcing -Wno-maybe-uninitialized on compilation of ipp compat library")
endif()

SET(IPP_COMPAT_SYMBOLS_FILE
	"${CMAKE_CURRENT_SOURCE_DIR}/ipp_compat_symbols.txt")
SET_PROPERTY(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
	"${IPP_COMPAT_SYMBOLS_FILE}")
FILE(STRINGS "${IPP_COMPAT_SYMBOLS_FILE}" IPP_COMPAT_SYMBOLS)

IF(WIN32)
	SET(IPP_COMPAT_DEF_FILE
		"${CMAKE_CURRENT_BINARY_DIR}/ipp_compat_exports.def")

	FILE(WRITE "${IPP_COMPAT_DEF_FILE}" "EXPORTS\n")
	FOREACH(IPP_COMPAT_SYMBOL IN LISTS IPP_COMPAT_SYMBOLS)
		FILE(APPEND "${IPP_COMPAT_DEF_FILE}" "    ${IPP_COMPAT_SYMBOL}\n")
	ENDFOREACH()
	TARGET_SOURCES(ipp-compat PRIVATE "${IPP_COMPAT_DEF_FILE}")

	TARGET_COMPILE_OPTIONS(ipp-compat PRIVATE -Wno-language-extension-token -Wno-missing-field-initializers)
ENDIF(WIN32)

IF(UNIX AND NOT APPLE AND ALCP_HIDDEN_VISIBILITY)
	SET(IPP_COMPAT_EXPORT_MAP
		"${CMAKE_CURRENT_BINARY_DIR}/ipp_compat_exports.map")
	FILE(WRITE "${IPP_COMPAT_EXPORT_MAP}" "{\n    global:\n")
	FOREACH(IPP_COMPAT_SYMBOL IN LISTS IPP_COMPAT_SYMBOLS)
		FILE(APPEND "${IPP_COMPAT_EXPORT_MAP}"
			"        ${IPP_COMPAT_SYMBOL};\n")
	ENDFOREACH()
	FILE(APPEND "${IPP_COMPAT_EXPORT_MAP}" "    local:\n        *;\n};\n")
	TARGET_LINK_OPTIONS(ipp-compat PRIVATE
		"-Wl,--version-script=${IPP_COMPAT_EXPORT_MAP}")
	SET_TARGET_PROPERTIES(ipp-compat PROPERTIES
		LINK_DEPENDS "${IPP_COMPAT_EXPORT_MAP}")
ENDIF()
