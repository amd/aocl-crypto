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


#
# The Policy will throw error about TARGET_SOURCES makes the
# relative paths as absolute
#

IF(POLICY CMP0076)
    CMAKE_POLICY(SET CMP0076 NEW)
ENDIF()

IF(POLICY CMP0079)
    CMAKE_POLICY(SET CMP0079 NEW)
ENDIF()


SET(ALCP_VRS_SRC
	version.cc)

SET(ALCP_COMMON_SRCS
	dynlib.cc
	error.cc
	exception.cc
	module.cc
	modulemanager.cc
	sourcelocation.cc
  status.cc
  bufferwriter.cc
  padding.cc
	)

INCLUDE(AlcpUtils)

# Get Compiler Flags, defined in cmake/Compiler*.cmake
alcp_get_cflags_warnings()
alcp_get_cflags()
alcp_get_cflags_debug()
alcp_get_cflags_arch()

IF (MSVC AND NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
	ADD_COMPILE_OPTIONS(/W3 /WX)
ELSEIF (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
	ADD_COMPILE_OPTIONS_CONFIG(RELEASE ${ALCP_CFLAGS} ${ALCP_CFLAGS_WARNINGS})
	ADD_COMPILE_OPTIONS_CONFIG(DEBUG ${ALCP_CFLAGS_DEBUG} ${ALCP_CFLAGS_WARNINGS})
	ADD_COMPILE_OPTIONS(${ALCP_CFLAGS_ARCH})
ELSE ()
	ADD_COMPILE_OPTIONS_CONFIG(RELEASE ${ALCP_CFLAGS} ${ALCP_CFLAGS_WARNINGS})
	ADD_COMPILE_OPTIONS_CONFIG(DEBUG ${ALCP_CFLAGS_DEBUG} ${ALCP_CFLAGS_WARNINGS})
ENDIF()

INCLUDE_DIRECTORIES(
	${CMAKE_SOURCE_DIR}/include
	)

SET(ALCP_LIB_SOURCES
	${ALCP_VRS_SRC}
	${ALCP_COMMON_SRCS}
	)

ADD_LIBRARY(alcp SHARED
	${ALCP_LIB_SOURCES}
	)

ADD_LIBRARY(alcp_static STATIC
	${ALCP_LIB_SOURCES}
	${ALCP_VRS_SRC}
	)

# Some linux distros will prefer RPATH not RUNPATH, enforce RUNPATH use
# RUNPATH will give priority to LD_LIBRARY_PATH, at last RUNPATH will use
# original path which was used in linking
TARGET_LINK_OPTIONS(alcp PUBLIC -Wl,--enable-new-dtags)

if(CMAKE_BUILD_TYPE STREQUAL "Coverage")
    alcp_add_coverage_flags()
endif()

IF(UNIX)
	SET_TARGET_PROPERTIES(alcp_static PROPERTIES OUTPUT_NAME alcp)
ENDIF(UNIX)

IF(WIN32)
	IF(EXISTS ${OPENSSL_INSTALL_DIR}/lib/libcrypto.lib)
		TARGET_LINK_LIBRARIES(alcp PUBLIC ${OPENSSL_INSTALL_DIR}/lib/libcrypto.lib)
		TARGET_LINK_LIBRARIES(alcp_static PUBLIC ${OPENSSL_INSTALL_DIR}/lib/libcrypto.lib)
	ENDIF()
ENDIF(WIN32)

INCLUDE_DIRECTORIES(${OPENSSL_INSTALL_DIR}/include)

TARGET_SOURCES(alcp
	PRIVATE
	${ALCP_LIB_SOURCES}
	)

TARGET_SOURCES(alcp_static
	PRIVATE
	${ALCP_LIB_SOURCES}
	)


enable_testing()

ADD_SUBDIRECTORY(arch)
ADD_SUBDIRECTORY(capi)
ADD_SUBDIRECTORY(compat)
ADD_SUBDIRECTORY(cipher)
ADD_SUBDIRECTORY(digest)
ADD_SUBDIRECTORY(ref)
ADD_SUBDIRECTORY(utils)
ADD_SUBDIRECTORY(rng)
ADD_SUBDIRECTORY(mac)
ADD_SUBDIRECTORY(ec)
ADD_SUBDIRECTORY(rsa)
ADD_SUBDIRECTORY(tests)

TARGET_INCLUDE_DIRECTORIES(alcp PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}/include)

TARGET_INCLUDE_DIRECTORIES(alcp_static PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}/include)

IF(UNIX AND ENABLE_AOCL_UTILS)
	TARGET_LINK_LIBRARIES(alcp PUBLIC dl)
	TARGET_LINK_LIBRARIES(alcp_static PUBLIC dl)
	IF(CMAKE_BUILD_TYPE STREQUAL "debug")
		ADD_CUSTOM_COMMAND(
			TARGET alcp_static POST_BUILD
			WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
			COMMAND /bin/bash 
			${CMAKE_SOURCE_DIR}/scripts/create_static.sh 
			${AOCL_UTILS_INSTALL_DIR}/lib/libaoclutils.a
			"DEBUG"
		)
 	ELSE()
		ADD_CUSTOM_COMMAND(
			TARGET alcp_static POST_BUILD
			WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
			COMMAND /bin/bash ${CMAKE_SOURCE_DIR}/scripts/create_static.sh 
			${AOCL_UTILS_INSTALL_DIR}/lib/libaoclutils.a
			""
		)
	ENDIF(CMAKE_BUILD_TYPE STREQUAL "debug")
ENDIF()

# Need to build comapt libs after building the libalcp.so
#${COMPAT_SRCS}
