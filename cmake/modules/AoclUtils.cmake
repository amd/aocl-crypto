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
	IF(AOCL_UTILS_INSTALL_DIR)
		MESSAGE(STATUS "AOCL_UTILS_INSTALL_DIR set, overriding fetch path")
	ELSE(AOCL_UTILS_INSTALL_DIR)
        ExternalProject_Add(aoclutils
            GIT_REPOSITORY git@github.amd.com:AOCL/aocl-utils.git
            GIT_TAG amd-main
            SOURCE_DIR "${CMAKE_BINARY_DIR}/external/src/aoclutils"
            BINARY_DIR "${EXTERNAL_INSTALL_LOCATION}/aoclutils"
            CMAKE_ARGS  -DAU_BUILD_DOCS=OFF -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=${EXTERNAL_INSTALL_LOCATION} "${CMAKE_BINARY_DIR}/external/src/aoclutils"
            BYPRODUCTS ${EXTERNAL_INSTALL_LOCATION}/lib/libaoclutils.so ${EXTERNAL_INSTALL_LOCATION}/lib/libaoclutils.a
        )

        add_dependencies(alcp aoclutils)
        add_dependencies(alcp_static aoclutils)

		# FIXME: Bug, binary not found in external directory!
		set(AOCL_UTILS_INSTALL_DIR ${EXTERNAL_INSTALL_LOCATION})

        # FIXME: Workaround, need to find, this directory is not being created - Possobily created as build time
		file(MAKE_DIRECTORY ${EXTERNAL_INSTALL_LOCATION})
		MESSAGE(STATUS "AOCL_UTILS_INSTALL_DIR not set, defaulting to external")
	ENDIF(AOCL_UTILS_INSTALL_DIR)
	IF(EXISTS ${AOCL_UTILS_INSTALL_DIR})
        set(AOCL_UTILS_STATIC_LIB ${AOCL_UTILS_INSTALL_DIR}/${CMAKE_INSTALL_LIBDIR}/libaoclutils.a)
        set(AOCL_UTILS_SHARED_LIB ${AOCL_UTILS_INSTALL_DIR}/${CMAKE_INSTALL_LIBDIR}/libaoclutils.so)
        set(AOCL_UTILS_INCLUDES   ${AOCL_UTILS_INSTALL_DIR}/include)
        TARGET_INCLUDE_DIRECTORIES(alcp PUBLIC ${AOCL_UTILS_INCLUDES})
		TARGET_INCLUDE_DIRECTORIES(alcp_static PUBLIC ${AOCL_UTILS_INCLUDES})
        IF(MSVC)
            # Dynamic
            TARGET_LINK_LIBRARIES(alcp PUBLIC ${AOCL_UTILS_INSTALL_DIR}/lib/libaoclutils.lib)
			TARGET_INCLUDE_DIRECTORIES(alcp PUBLIC ${AOCL_UTILS_INSTALL_DIR}/lib)
			TARGET_COMPILE_OPTIONS(alcp PRIVATE "-Wno-microsoft-enum-value")

            # Static
			TARGET_LINK_LIBRARIES(alcp_static PUBLIC ${AOCL_UTILS_INSTALL_DIR}/lib/libaoclutils.lib)
        ELSE(MSVC)
			TARGET_LINK_LIBRARIES(alcp PRIVATE ${AOCL_UTILS_SHARED_LIB})
			TARGET_LINK_LIBRARIES(alcp_static PRIVATE ${AOCL_UTILS_STATIC_LIB})
        ENDIF() 
	ELSE(EXISTS ${AOCL_UTILS_INSTALL_DIR})
		MESSAGE(FATAL_ERROR "AOCL UTILS fallback error, external directory not found!")
	ENDIF(EXISTS ${AOCL_UTILS_INSTALL_DIR})
ENDIF(ENABLE_AOCL_UTILS)