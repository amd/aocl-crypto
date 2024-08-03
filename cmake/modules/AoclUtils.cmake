 # Copyright (C) 2024, Advanced Micro Devices. All rights reserved.
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
	set(EXTERNAL_INSTALL_LOCATION "${CMAKE_BINARY_DIR}/external")
    set(AOCL_UTILS_SRC "${CMAKE_BINARY_DIR}/external/src/aoclutils")
	FetchContent_Declare(aoclutils
		GIT_REPOSITORY git@github.amd.com:AOCL/aocl-utils.git
		GIT_TAG amd-main
		SOURCE_DIR ${AOCL_UTILS_SRC}
		BINARY_DIR "${EXTERNAL_INSTALL_LOCATION}/aoclutils"
	)
	IF(AOCL_UTILS_INSTALL_DIR)
		MESSAGE(STATUS "AOCL_UTILS_INSTALL_DIR set, overriding fetch path")
		set(AOCL_UTILS_STATIC_LIB ${AOCL_UTILS_INSTALL_DIR}/${CMAKE_INSTALL_LIBDIR}/libaoclutils.a PARENT_SCOPE)
	ELSE(AOCL_UTILS_INSTALL_DIR)
		# FIXME: Bug, binary not found in external directory!
		set(AOCL_UTILS_STATIC_LIB ${CMAKE_BINARY_DIR}/libaoclutils.a PARENT_SCOPE)
		set(AOCL_UTILS_INSTALL_DIR ${EXTERNAL_INSTALL_LOCATION}/aoclutils)

        # # FIXME: Workaround, need to find, this directory is not being created - Possobily created as build time
		# file(MAKE_DIRECTORY ${EXTERNAL_INSTALL_LOCATION}/aoclutils)
		MESSAGE(STATUS "AOCL_UTILS_INSTALL_DIR not set, defaulting to external")
		FetchContent_MakeAvailable(aoclutils)
		set(AOCL_UTILS_FETCHED ON)
	ENDIF(AOCL_UTILS_INSTALL_DIR)
	IF(EXISTS ${AOCL_UTILS_INSTALL_DIR} AND IS_DIRECTORY ${AOCL_UTILS_INSTALL_DIR})
        add_library(aoclutils-shared SHARED IMPORTED)
        add_library(aoclutils-static STATIC IMPORTED)
        IF(MSVC)
            set_target_properties(aoclutils-shared PROPERTIES
                IMPORTED_LOCATION   ${AOCL_UTILS_INSTALL_DIR}/bin/libaoclutils.dll
                IMPORTED_IMPLIB     ${AOCL_UTILS_INSTALL_DIR}/bin/libaoclutils.lib
                COMPILE_OPTIONS "-Wno-microsoft-enum-value"
            ) 
            set_target_properties(aoclutils-static PROPERTIES
                IMPORTED_LOCATION   ${AOCL_UTILS_INSTALL_DIR}/bin/libaoclutils.lib
            )  
            target_include_directories(aoclutils-shared INTERFACE ${AOCL_UTILS_INSTALL_DIR}/include)
            target_include_directories(aoclutils-static INTERFACE ${AOCL_UTILS_INSTALL_DIR}/include)
        ELSE(MSVC)
            IF(AOCL_UTILS_FETCHED)
                set_target_properties(aoclutils-shared PROPERTIES
                    IMPORTED_LOCATION   ${CMAKE_BINARY_DIR}/libaoclutils.so
                    INCLUDE_DIRECTORIES ${AOCL_UTILS_SRC}/SDK/Include
                    INTERFACE_INCLUDE_DIRECTORIES ${AOCL_UTILS_SRC}/SDK/Include
                )  
                target_include_directories(aoclutils-shared INTERFACE ${AOCL_UTILS_SRC}/SDK/Include)
                set_target_properties(aoclutils-static PROPERTIES
                    IMPORTED_LOCATION   ${CMAKE_BINARY_DIR}/libaoclutils.a
                    INCLUDE_DIRECTORIES ${AOCL_UTILS_SRC}/SDK/Include
                    INTERFACE_INCLUDE_DIRECTORIES ${AOCL_UTILS_SRC}/SDK/Include
                )
                target_include_directories(aoclutils-static INTERFACE ${AOCL_UTILS_SRC}/SDK/Include)
            ELSE(AOCL_UTILS_FETCHED)
                set_target_properties(aoclutils-shared PROPERTIES
                    IMPORTED_LOCATION   ${AOCL_UTILS_INSTALL_DIR}/${CMAKE_INSTALL_LIBDIR}/libaoclutils.so
                    INCLUDE_DIRECTORIES ${AOCL_UTILS_INSTALL_DIR}/include
                )      
                target_include_directories(aoclutils-shared INTERFACE ${AOCL_UTILS_INSTALL_DIR}/include)
                set_target_properties(aoclutils-static PROPERTIES
                    IMPORTED_LOCATION   ${AOCL_UTILS_INSTALL_DIR}/${CMAKE_INSTALL_LIBDIR}/libaoclutils.a
                    INCLUDE_DIRECTORIES ${AOCL_UTILS_INSTALL_DIR}/include
                )  
                target_include_directories(aoclutils-static INTERFACE ${AOCL_UTILS_INSTALL_DIR}/include)
            ENDIF()
        ENDIF() 
	ELSE(EXISTS ${AOCL_UTILS_INSTALL_DIR} AND IS_DIRECTORY ${AOCL_UTILS_INSTALL_DIR})
		MESSAGE(FATAL_ERROR "AOCL UTILS fallback error, external directory not found!")
	ENDIF(EXISTS ${AOCL_UTILS_INSTALL_DIR} AND IS_DIRECTORY ${AOCL_UTILS_INSTALL_DIR})
ENDIF(ENABLE_AOCL_UTILS)