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
	error.cc
	exception.cc
	module.cc
	modulemanager.cc
	sourcelocation.cc
	status.cc
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
	ADD_COMPILE_OPTIONS_CONFIG(RELEASE ${ALCP_CFLAGS_WARNINGS} ${ALCP_CFLAGS})
	ADD_COMPILE_OPTIONS_CONFIG(DEBUG ${ALCP_CFLAGS_WARNINGS} ${ALCP_CFLAGS_DEBUG})
	ADD_COMPILE_OPTIONS(${ALCP_CFLAGS_ARCH})
ELSE ()
	ADD_COMPILE_OPTIONS_CONFIG(RELEASE ${ALCP_CFLAGS_WARNINGS} ${ALCP_CFLAGS})
	ADD_COMPILE_OPTIONS_CONFIG(DEBUG ${ALCP_CFLAGS_WARNINGS} ${ALCP_CFLAGS_DEBUG})
ENDIF()

INCLUDE_DIRECTORIES(
	${ALCP_ROOT}/include
	)

SET(ALCP_LIB_SOURCES
	${ALCP_VRS_SRC}
	${ALCP_COMMON_SRCS}
	)

# Create only the requested library targets. Sub-directories use the
# ALCP_TARGET_* helpers (which guard on IF(TARGET alcp) / IF(TARGET alcp_static)),
# so a disabled library is simply never built.
IF(ALCP_BUILD_SHARED)
	ADD_LIBRARY(alcp SHARED ${ALCP_LIB_SOURCES})
ENDIF()

IF(ALCP_BUILD_STATIC)
	ADD_LIBRARY(alcp_static STATIC ${ALCP_LIB_SOURCES} ${ALCP_VRS_SRC})
ENDIF()

# Position-independent code so alcp_static can be linked into a shared object
# (e.g. a compat plugin) on Linux. No-op on Windows.
IF(TARGET alcp_static)
	SET_TARGET_PROPERTIES(alcp_static PROPERTIES POSITION_INDEPENDENT_CODE ON)
ENDIF()

# Some linux distros will prefer RPATH not RUNPATH, enforce RUNPATH use
IF(UNIX AND TARGET alcp)
	TARGET_LINK_OPTIONS(alcp PUBLIC -Wl,--enable-new-dtags)
ENDIF()

IF(UNIX AND TARGET alcp_static)
	SET_TARGET_PROPERTIES(alcp_static PROPERTIES OUTPUT_NAME alcp)
ENDIF()

IF(WIN32)
	IF(EXISTS ${OPENSSL_INSTALL_DIR}/lib/libcrypto.lib)
		IF(TARGET alcp)
			TARGET_LINK_LIBRARIES(alcp PUBLIC ${OPENSSL_INSTALL_DIR}/lib/libcrypto.lib)
		ENDIF()
		IF(TARGET alcp_static)
			TARGET_LINK_LIBRARIES(alcp_static PUBLIC ${OPENSSL_INSTALL_DIR}/lib/libcrypto.lib)
		ENDIF()
	ENDIF()
ENDIF(WIN32)

INCLUDE_DIRECTORIES(${OPENSSL_INSTALL_DIR}/include)

IF(TARGET alcp)
	TARGET_SOURCES(alcp PRIVATE ${ALCP_LIB_SOURCES})
ENDIF()

IF(TARGET alcp_static)
	TARGET_SOURCES(alcp_static PRIVATE ${ALCP_LIB_SOURCES})
ENDIF()


enable_testing()

ADD_SUBDIRECTORY(utils)
ADD_SUBDIRECTORY(cipher)
ADD_SUBDIRECTORY(digest)
ADD_SUBDIRECTORY(rng)
ADD_SUBDIRECTORY(compat)
ADD_SUBDIRECTORY(mac)
ADD_SUBDIRECTORY(ec)
ADD_SUBDIRECTORY(rsa)
ADD_SUBDIRECTORY(ref)
ADD_SUBDIRECTORY(arch)
ADD_SUBDIRECTORY(capi)
ADD_SUBDIRECTORY(tests)

# check if build type is coverage - apply after all targets are defined
string(TOUPPER "${CMAKE_BUILD_TYPE}" BUILD_TYPE_UPPER)
if(BUILD_TYPE_UPPER STREQUAL "COVERAGE")
    alcp_add_coverage_flags()
endif()

IF(TARGET alcp)
	TARGET_INCLUDE_DIRECTORIES(alcp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
ENDIF()

IF(TARGET alcp_static)
	TARGET_INCLUDE_DIRECTORIES(alcp_static PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
ENDIF()

# Combined-static: merge libalcp + static aocl-utils into one archive with
# ${CMAKE_AR}. Linux uses `ar -M addlib`; Windows uses lib/llvm-lib /OUT:.
# Run as a build-time command that DEPENDS on the aoclutils target when fetched.
IF(ENABLE_AOCL_UTILS AND ALCP_INSTALL_COMBINED_STATIC AND ALCP_BUILD_STATIC)
	IF(NOT CMAKE_AR)
		MESSAGE(FATAL_ERROR
			"ALCP_INSTALL_COMBINED_STATIC needs an archiver but CMAKE_AR is unset. "
			"The C/C++ toolchain archiver (binutils/llvm-ar on Linux, lib/llvm-lib "
			"on Windows) is missing. Install the matching toolchain and re-run cmake.")
	ENDIF()

	# Depend on the aoclutils target only in the fetch path.
	SET(_ALCP_COMBINED_DEPS alcp_static)
	IF(TARGET aoclutils)
		LIST(APPEND _ALCP_COMBINED_DEPS aoclutils)
	ENDIF()

	IF(WIN32)
		SET(_ALCP_COMBINED_LIB ${CMAKE_BINARY_DIR}/libalcp_static.lib)
		# Windows merge needs MSVC-style lib/llvm-lib (/OUT:), not GNU ar.
		GET_FILENAME_COMPONENT(_ALCP_AR_NAME "${CMAKE_AR}" NAME_WE)
		STRING(TOLOWER "${_ALCP_AR_NAME}" _ALCP_AR_NAME)
		IF(NOT _ALCP_AR_NAME STREQUAL "lib" AND NOT _ALCP_AR_NAME STREQUAL "llvm-lib")
			MESSAGE(FATAL_ERROR
				"Combined-static on Windows merges archives with lib.exe/llvm-lib "
				"'/OUT:' syntax, but CMAKE_AR='${CMAKE_AR}' is not a recognised "
				"MSVC-style archiver (expected 'lib' or 'llvm-lib'). Use the MSVC "
				"or ClangCl toolchain so CMake selects a compatible archiver.")
		ENDIF()
		# Merge the static archive, not the DLL import stub, so the result is
		# self-contained. Skip the check on the fetch path (built lazily).
		IF(NOT TARGET aoclutils AND NOT EXISTS "${_AOCL_UTILS_WIN_STATIC_LIB}")
			MESSAGE(FATAL_ERROR "Combined-static needs the static aocl-utils lib "
				"but it was not found: '${_AOCL_UTILS_WIN_STATIC_LIB}'. Provide an "
				"aocl-utils install built with BUILD_SHARED_LIBS=OFF via "
				"AOCL_UTILS_INSTALL_DIR.")
		ENDIF()
		# lib.exe / llvm-lib merges static libs directly.
		ADD_CUSTOM_COMMAND(
			OUTPUT ${_ALCP_COMBINED_LIB}
			COMMAND ${CMAKE_AR} /OUT:${_ALCP_COMBINED_LIB}
				$<TARGET_FILE:alcp_static> ${_AOCL_UTILS_WIN_STATIC_LIB}
			DEPENDS ${_ALCP_COMBINED_DEPS}
			COMMENT "Combining alcp_static.lib + libaoclutils_static.lib -> libalcp_static.lib")
	ELSE()
		IF(TARGET alcp)
			TARGET_LINK_LIBRARIES(alcp PUBLIC dl)
		ENDIF()
		TARGET_LINK_LIBRARIES(alcp_static PUBLIC dl)

		SET(_ALCP_COMBINED_LIB ${CMAKE_BINARY_DIR}/libalcp_static.a)

		# Skip on the fetch path (built lazily); guard a pre-installed shared-only utils.
		IF(NOT TARGET aoclutils AND NOT EXISTS "${AOCL_UTILS_STATIC_LIB}")
			MESSAGE(FATAL_ERROR "Combined-static needs libaoclutils.a but it was not found: '${AOCL_UTILS_STATIC_LIB}'. Provide a static aocl-utils via AOCL_UTILS_INSTALL_DIR.")
		ENDIF()

		# `ar -M addlib` copies members archive-to-archive, preserving duplicate
		# basenames (per-arch object sources) that `ar x` would flatten.
		FILE(GENERATE
			OUTPUT  ${CMAKE_BINARY_DIR}/combine_static.mri
			CONTENT "create ${_ALCP_COMBINED_LIB}
addlib $<TARGET_FILE:alcp_static>
addlib ${AOCL_UTILS_STATIC_LIB}
save
end
")
		ADD_CUSTOM_COMMAND(
			OUTPUT ${_ALCP_COMBINED_LIB}
			COMMAND ${CMAKE_COMMAND} -E rm -f ${_ALCP_COMBINED_LIB}
			COMMAND /bin/sh -c "${CMAKE_AR} -M < ${CMAKE_BINARY_DIR}/combine_static.mri"
			DEPENDS ${_ALCP_COMBINED_DEPS} ${CMAKE_BINARY_DIR}/combine_static.mri
			VERBATIM
			COMMENT "Combining libalcp.a + libaoclutils.a -> libalcp_static.a (ar -M addlib)")
	ENDIF()

	# A target that always builds the combined archive, and a stable name other
	# targets (e.g. the combined_static_link test) can depend on.
	ADD_CUSTOM_TARGET(alcp_combined_static ALL DEPENDS ${_ALCP_COMBINED_LIB})
ENDIF()

# AOCL Build-It-Yourself unified build: contribute crypto's objects to libaocl.
# The core ALCP sources funnelled into alcp_static (version/common plus every
# subdirectory's TARGET_SOURCES) are recompiled into a sibling OBJECT library via
# objectify. The architecture kernels (arch_zen4, arch_zen4_gcm, arch_zen3,
# arch_zen, arch_ref, arch_avx2) are OBJECT libraries linked PRIVATE into
# alcp_static; object libraries do not propagate their objects through another
# object library, so they are registered directly by walking alcp_static's link
# dependencies. Placed at the end of the file so SOURCES and LINK_LIBRARIES are
# fully populated by all sub-directories.
if(AOCL_TB_UNIFIED_BUILD)
	aocl_tb_objectify(alcp_static)
	get_target_property(_alcp_links alcp_static LINK_LIBRARIES)
	set(_alcp_arch_objs "")
	foreach(_l IN LISTS _alcp_links)
		if(TARGET ${_l})
			get_target_property(_lt ${_l} TYPE)
			if(_lt STREQUAL "OBJECT_LIBRARY")
				list(APPEND _alcp_arch_objs "$<TARGET_OBJECTS:${_l}>")
			endif()
		endif()
	endforeach()
	if(_alcp_arch_objs)
		aocl_tb_add_objects(${_alcp_arch_objs})
	endif()
endif()

# Need to build comapt libs after building the libalcp.so
#${COMPAT_SRCS}
