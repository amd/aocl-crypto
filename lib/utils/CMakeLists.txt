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

include(ExternalProject)
include(FetchContent)


# Enable UTILS if enabled and available
IF(ENABLE_AOCL_UTILS)
	MESSAGE(STATUS "Enabling AOCL UTILS Support")
	IF(AOCL_UTILS_INSTALL_DIR)
		MESSAGE(STATUS "AOCL_UTILS_INSTALL_DIR set, overriding fetch path")
		set(AOCL_UTILS_STATIC_LIB ${AOCL_UTILS_INSTALL_DIR}/${CMAKE_INSTALL_LIBDIR}/libau_cpuid.a PARENT_SCOPE)
	ELSE(AOCL_UTILS_INSTALL_DIR)
		# FIXME: Move this to lib parent scope in future
		set(EXTERNAL_INSTALL_LOCATION ${CMAKE_BINARY_DIR})
		set(AOCL_UTILS_STATIC_LIB ${EXTERNAL_INSTALL_LOCATION}/libau_cpuid.a PARENT_SCOPE)
		set(AOCL_UTILS_INSTALL_DIR ${EXTERNAL_INSTALL_LOCATION})
		file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/external)
		MESSAGE(STATUS "AOCL_UTILS_INSTALL_DIR not set, defaulting to external")
		FetchContent_Declare(aoclutils
			GIT_REPOSITORY git@github.amd.com:AOCL/aocl-utils.git
			GIT_TAG amd-main
			SOURCE_DIR "${CMAKE_BINARY_DIR}/external/src/aoclutils"
			BINARY_DIR "${CMAKE_BINARY_DIR}/external/aoclutils"
		)
		FetchContent_MakeAvailable(aoclutils)
		set(AOCL_UTILS_FETCHED ON)
	ENDIF(AOCL_UTILS_INSTALL_DIR)
	IF(EXISTS ${AOCL_UTILS_INSTALL_DIR} AND IS_DIRECTORY ${AOCL_UTILS_INSTALL_DIR})
		TARGET_INCLUDE_DIRECTORIES(alcp PUBLIC ${AOCL_UTILS_INSTALL_DIR}/include)
		TARGET_INCLUDE_DIRECTORIES(alcp_static PUBLIC ${AOCL_UTILS_INSTALL_DIR}/include)
		IF(MSVC)
			TARGET_LINK_LIBRARIES(alcp PUBLIC ${AOCL_UTILS_INSTALL_DIR}/lib/au_cpuid.lib)
			TARGET_INCLUDE_DIRECTORIES(alcp PUBLIC ${AOCL_UTILS_INSTALL_DIR}/bin)
			TARGET_COMPILE_OPTIONS(alcp PRIVATE "-Wno-microsoft-enum-value")

			TARGET_LINK_LIBRARIES(alcp_static PUBLIC ${AOCL_UTILS_INSTALL_DIR}/lib/au_cpuid.lib)
		ELSE()
 			IF(AOCL_UTILS_FETCHED)
				TARGET_LINK_LIBRARIES(alcp PRIVATE aoclutils)
				TARGET_LINK_LIBRARIES(alcp_static PRIVATE aoclutils)
			ELSE(AOCL_UTILS_FETCHED)
				TARGET_LINK_LIBRARIES(alcp PRIVATE ${AOCL_UTILS_INSTALL_DIR}/${CMAKE_INSTALL_LIBDIR}/libau_cpuid.so)
				TARGET_LINK_LIBRARIES(alcp_static PRIVATE ${AOCL_UTILS_INSTALL_DIR}/${CMAKE_INSTALL_LIBDIR}/libau_cpuid.a)
			ENDIF()
		ENDIF()
	ELSE(EXISTS ${AOCL_UTILS_INSTALL_DIR} AND IS_DIRECTORY ${AOCL_UTILS_INSTALL_DIR})
		MESSAGE(FATAL_ERROR "AOCL UTILS fallback error, external directory not found!")
	ENDIF(EXISTS ${AOCL_UTILS_INSTALL_DIR} AND IS_DIRECTORY ${AOCL_UTILS_INSTALL_DIR})
ENDIF(ENABLE_AOCL_UTILS)

SET(UTILS_SRCS
  bignum.cc
  logger.cc
  #mempool.cc
  console_logger.cc
  cpuid.cc
  memory.cc
  )

IF (ALCP_ENABLE_TESTS)
  ADD_SUBDIRECTORY(tests)
ENDIF()

TARGET_SOURCES(alcp
	PRIVATE
		${UTILS_SRCS}
	)

TARGET_SOURCES(alcp_static
	PRIVATE
		${UTILS_SRCS}
	)

IF(UNIX)
  IF (NOT IS_DIRECTORY ${OPENSSL_INSTALL_DIR})
    MESSAGE(FATAL_ERROR "OpenSSL installation dir not found!")
  ENDIF ()
  IF(EXISTS ${OPENSSL_INSTALL_DIR}/lib64/libcrypto.so)
    TARGET_LINK_LIBRARIES(alcp PUBLIC ${OPENSSL_INSTALL_DIR}/lib64/libcrypto.so)
    TARGET_LINK_LIBRARIES(alcp_static PUBLIC ${OPENSSL_INSTALL_DIR}/lib64/libcrypto.so)
  ELSEIF(EXISTS ${OPENSSL_INSTALL_DIR}/lib/libcrypto.so)
    TARGET_LINK_LIBRARIES(alcp PUBLIC ${OPENSSL_INSTALL_DIR}/lib/libcrypto.so)
    TARGET_LINK_LIBRARIES(alcp_static PUBLIC ${OPENSSL_INSTALL_DIR}/lib/libcrypto.so)
  ELSEIF(EXISTS ${OPENSSL_INSTALL_DIR}/lib/x86_64-linux-gnu/libcrypto.so)
    TARGET_LINK_LIBRARIES(alcp PUBLIC ${OPENSSL_INSTALL_DIR}/lib/x86_64-linux-gnu/libcrypto.so)
    TARGET_LINK_LIBRARIES(alcp_static PUBLIC ${OPENSSL_INSTALL_DIR}/lib/x86_64-linux-gnu/libcrypto.so)
  ELSE()
    TARGET_LINK_LIBRARIES(alcp PUBLIC ${OPENSSL_INSTALL_DIR}/x86_64-linux-gnu/libcrypto.so)
    TARGET_LINK_LIBRARIES(alcp_static PUBLIC ${OPENSSL_INSTALL_DIR}/x86_64-linux-gnu/libcrypto.so)
  ENDIF()
ENDIF(UNIX)


