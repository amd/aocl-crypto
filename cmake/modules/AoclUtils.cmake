 # Copyright (C) 2024-2026, Advanced Micro Devices. All rights reserved.
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

# Enable UTILS if enabled and available
IF(ENABLE_AOCL_UTILS)
	MESSAGE(STATUS "Implementing AOCL-UTILS imported library")
	# AOCL-BIY in-tree build: when AOCL-Utils is already an in-tree CMake target
	# (FetchContent + add_subdirectory), link it directly instead of locating a
	# staged/installed package. The target carries its own usage requirements
	# (include dirs), so no install layout is required.
	IF(TARGET aoclutils)
		MESSAGE(STATUS "AOCL-UTILS in-tree target found, linking directly")
		TARGET_LINK_LIBRARIES(alcp PUBLIC aoclutils)
		TARGET_LINK_LIBRARIES(alcp_static PUBLIC aoclutils)
		IF(AOCL_TB_UTILS_INCLUDE_DIRS)
			TARGET_INCLUDE_DIRECTORIES(alcp PUBLIC ${AOCL_TB_UTILS_INCLUDE_DIRS})
			TARGET_INCLUDE_DIRECTORIES(alcp_static PUBLIC ${AOCL_TB_UTILS_INCLUDE_DIRS})
		ENDIF()
		IF(MSVC)
			TARGET_COMPILE_OPTIONS(alcp PRIVATE "-Wno-microsoft-enum-value")
		ENDIF()
		RETURN()
	ENDIF()
	# aocl-utils applies CMAKE_DEBUG_POSTFIX ("-dbg") in Debug, so its libraries
	# may be named libaoclutils-dbg.* etc. Resolve the suffix once; the cached
	# name variables below reuse it.
	#  - Pre-installed (AOCL_UTILS_INSTALL_DIR): its configuration is independent
	#    of ALCP's, so detect the suffix from the files on disk.
	#  - Fetched (ExternalProject): built with ALCP's CMAKE_BUILD_TYPE and not yet
	#    present at configure time, so derive the suffix from the build type.
	IF(AOCL_UTILS_INSTALL_DIR)
		SET(_AU_SFX "")
		FOREACH(_au_dbg_probe
			"${AOCL_UTILS_INSTALL_DIR}/lib/libaoclutils-dbg.lib"
			"${AOCL_UTILS_INSTALL_DIR}/lib/libaoclutils_static-dbg.lib"
			"${AOCL_UTILS_INSTALL_DIR}/${CMAKE_INSTALL_LIBDIR}/libaoclutils-dbg.so"
			"${AOCL_UTILS_INSTALL_DIR}/${CMAKE_INSTALL_LIBDIR}/libaoclutils-dbg.a")
			IF(EXISTS "${_au_dbg_probe}")
				SET(_AU_SFX "-dbg")
			ENDIF()
		ENDFOREACH()
	ELSE()
		STRING(TOUPPER "${CMAKE_BUILD_TYPE}" _AOCL_UTILS_BUILD_TYPE)
		IF(_AOCL_UTILS_BUILD_TYPE STREQUAL "DEBUG")
			SET(_AU_SFX "-dbg")
		ELSE()
			SET(_AU_SFX "")
		ENDIF()
	ENDIF()
	# Only the single aoclutils binary is referenced: the cpuid module is
	# compiled into libaoclutils (au_cpuid is a strict subset of it), so there is
	# no separate au_cpuid dependency.
	# Unix library file names (.so / .a).
	SET(AU_UTILS_SHARED_LIBNAME "libaoclutils${_AU_SFX}.so"         CACHE INTERNAL "aocl-utils shared lib file name")
	SET(AU_UTILS_STATIC_LIBNAME "libaoclutils${_AU_SFX}.a"          CACHE INTERNAL "aocl-utils static lib file name")
	# Windows library file names (.lib): DLL import lib + static lib.
	SET(AU_UTILS_IMPORT_LIBNAME "libaoclutils${_AU_SFX}.lib"        CACHE INTERNAL "aocl-utils DLL import lib file name")
	SET(AU_UTILS_STATIC_WINLIB  "libaoclutils_static${_AU_SFX}.lib" CACHE INTERNAL "aocl-utils static lib file name (Windows)")
	set(EXTERNAL_INSTALL_LOCATION "${CMAKE_BINARY_DIR}/external")
    set(AOCL_UTILS_SRC "${CMAKE_BINARY_DIR}/external/src/aoclutils")
	IF(AOCL_UTILS_INSTALL_DIR)
		MESSAGE(STATUS "AOCL_UTILS_INSTALL_DIR set, overriding fetch path")
	ELSE(AOCL_UTILS_INSTALL_DIR)
        # Match the fetched aocl-utils CRT to ALCP: shared -> /MD (ships static
        # too), static-only -> /MT static-only.
        IF(ALCP_BUILD_SHARED)
            SET(_AOCL_UTILS_FETCH_SHARED ON)
        ELSE()
            SET(_AOCL_UTILS_FETCH_SHARED OFF)
        ENDIF()
        # Build the fetched aocl-utils with ALCP's own toolchain; the default
        # would pick a GNU-driver clang that emits -fPIC and fails clang-cl.
        ExternalProject_Add(aoclutils
            GIT_REPOSITORY https://github.com/amd/aocl-utils.git
            GIT_TAG dev
            SOURCE_DIR "${CMAKE_BINARY_DIR}/external/src/aoclutils"
            BINARY_DIR "${EXTERNAL_INSTALL_LOCATION}/aoclutils"
            CMAKE_GENERATOR "${CMAKE_GENERATOR}"
            CMAKE_GENERATOR_PLATFORM "${CMAKE_GENERATOR_PLATFORM}"
            CMAKE_GENERATOR_TOOLSET "${CMAKE_GENERATOR_TOOLSET}"
            CMAKE_ARGS  -DAU_BUILD_DOCS=OFF -DBUILD_SHARED_LIBS=${_AOCL_UTILS_FETCH_SHARED}
                        -DCMAKE_INSTALL_PREFIX=${EXTERNAL_INSTALL_LOCATION}
                        -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
                        -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
                        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
                        "${CMAKE_BINARY_DIR}/external/src/aoclutils"
            BYPRODUCTS ${EXTERNAL_INSTALL_LOCATION}/${CMAKE_INSTALL_LIBDIR}/${AU_UTILS_SHARED_LIBNAME} ${EXTERNAL_INSTALL_LOCATION}/${CMAKE_INSTALL_LIBDIR}/${AU_UTILS_STATIC_LIBNAME}
                       # Windows .lib byproducts so the build system knows the
                       # fetch build produces them before linking alcp / examples.
                       ${EXTERNAL_INSTALL_LOCATION}/lib/${AU_UTILS_IMPORT_LIBNAME} ${EXTERNAL_INSTALL_LOCATION}/lib/${AU_UTILS_STATIC_WINLIB}
        )

        IF(TARGET alcp)
            add_dependencies(alcp aoclutils)
        ENDIF()
        IF(TARGET alcp_static)
            add_dependencies(alcp_static aoclutils)
        ENDIF()

		set(AOCL_UTILS_INSTALL_DIR ${EXTERNAL_INSTALL_LOCATION} CACHE STRING "AOCL UTILS INSTALLED DIRECTORY" FORCE)

        # FIXME: Workaround, need to find, this directory is not being created - Possobily created as build time
		file(MAKE_DIRECTORY ${EXTERNAL_INSTALL_LOCATION})
		MESSAGE(STATUS "AOCL_UTILS_INSTALL_DIR not set, defaulting to external")
	ENDIF(AOCL_UTILS_INSTALL_DIR)
	IF(EXISTS ${AOCL_UTILS_INSTALL_DIR})
        set(AOCL_UTILS_STATIC_LIB ${AOCL_UTILS_INSTALL_DIR}/${CMAKE_INSTALL_LIBDIR}/${AU_UTILS_STATIC_LIBNAME})
        set(AOCL_UTILS_SHARED_LIB ${AOCL_UTILS_INSTALL_DIR}/${CMAKE_INSTALL_LIBDIR}/${AU_UTILS_SHARED_LIBNAME})
        set(AOCL_UTILS_INCLUDES   ${AOCL_UTILS_INSTALL_DIR}/include)
        # Propagate to parent scope so lib/CMakeLists.txt (which include()s this
        # file via lib/utils/CMakeLists.txt) can see these variables when
        # building the combined static archive (ALCP_INSTALL_COMBINED_STATIC).
        set(AOCL_UTILS_STATIC_LIB ${AOCL_UTILS_STATIC_LIB} PARENT_SCOPE)
        set(AOCL_UTILS_SHARED_LIB ${AOCL_UTILS_SHARED_LIB} PARENT_SCOPE)
        set(AOCL_UTILS_INCLUDES   ${AOCL_UTILS_INCLUDES}   PARENT_SCOPE)
        ALCP_TARGET_INCLUDE_DIRECTORIES(PUBLIC ${AOCL_UTILS_INCLUDES})
        IF(MSVC)
            # Pick the right aocl-utils variant: the import library
            # (libaoclutils.lib) for shared builds, or the static library
            # (libaoclutils_static.lib) for static-only builds.
            IF(ALCP_BUILD_SHARED)
                SET(_AOCL_UTILS_WIN_LIB ${AOCL_UTILS_INSTALL_DIR}/lib/${AU_UTILS_IMPORT_LIBNAME})
            ELSE()
                SET(_AOCL_UTILS_WIN_LIB ${AOCL_UTILS_INSTALL_DIR}/lib/${AU_UTILS_STATIC_WINLIB})
            ENDIF()
            # A static ALCP needs the static aocl-utils lib; fail early if absent.
            SET(_AOCL_UTILS_WIN_STATIC_LIB ${AOCL_UTILS_INSTALL_DIR}/lib/${AU_UTILS_STATIC_WINLIB})
            # Fetch path builds it lazily, so only enforce for a pre-installed
            # aocl-utils (no aoclutils target).
            IF(ALCP_BUILD_STATIC AND NOT TARGET aoclutils AND NOT EXISTS "${_AOCL_UTILS_WIN_STATIC_LIB}")
                MESSAGE(FATAL_ERROR
                    "ALCP static library requested but the static aocl-utils lib "
                    "was not found:\n    '${_AOCL_UTILS_WIN_STATIC_LIB}'\n"
                    "A static ALCP (ALCP_BUILD_STATIC=ON, and especially "
                    "ALCP_BUILD_SHARED=OFF or ALCP_INSTALL_COMBINED_STATIC=ON) needs "
                    "a static aocl-utils. Provide an aocl-utils install built with "
                    "BUILD_SHARED_LIBS=OFF (which ships libaoclutils_static.lib) via "
                    "AOCL_UTILS_INSTALL_DIR, or set ALCP_BUILD_SHARED=ON to use the "
                    "shared aocl-utils import library instead.")
            ENDIF()
            # Export to parent scope so the combined-static merge in
            # lib/CMakeLists.txt can reference the Windows static lib.
            SET(_AOCL_UTILS_WIN_LIB ${_AOCL_UTILS_WIN_LIB} PARENT_SCOPE)
            SET(_AOCL_UTILS_WIN_STATIC_LIB ${_AOCL_UTILS_WIN_STATIC_LIB} PARENT_SCOPE)
            IF(TARGET alcp)
                TARGET_LINK_LIBRARIES(alcp PUBLIC ${_AOCL_UTILS_WIN_LIB})
                TARGET_INCLUDE_DIRECTORIES(alcp PUBLIC ${AOCL_UTILS_INSTALL_DIR}/lib)
                TARGET_COMPILE_OPTIONS(alcp PRIVATE "-Wno-microsoft-enum-value")
            ENDIF()
            IF(TARGET alcp_static)
                TARGET_LINK_LIBRARIES(alcp_static PUBLIC ${_AOCL_UTILS_WIN_LIB})
            ENDIF()
        ELSE(MSVC)
            IF(TARGET alcp)
                TARGET_LINK_LIBRARIES(alcp PRIVATE ${AOCL_UTILS_SHARED_LIB})
            ENDIF()
            IF(TARGET alcp_static)
                TARGET_LINK_LIBRARIES(alcp_static PRIVATE ${AOCL_UTILS_STATIC_LIB})
            ENDIF()
        ENDIF() 
	ELSE(EXISTS ${AOCL_UTILS_INSTALL_DIR})
		MESSAGE(FATAL_ERROR "AOCL UTILS fallback error, external directory not found!")
	ENDIF(EXISTS ${AOCL_UTILS_INSTALL_DIR})
ENDIF(ENABLE_AOCL_UTILS)
