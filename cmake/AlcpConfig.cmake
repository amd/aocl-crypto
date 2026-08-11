# Copyright (C) 2023-2026, Advanced Micro Devices. All rights reserved.
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

INCLUDE(CheckCXXSymbolExists)

FUNCTION(GEN_CONF)
    # Set ALCP Release Version String
    STRING(TIMESTAMP ALCP_RELEASE_VERSION_STRING "AOCL-Crypto ${AOCL_RELEASE_VERSION} Build %Y%m%d")

    OPTION(ALCP_ENABLE_DEBUG_LOGGING "ENABLE DEBUG PRINTS INSIDE ALCP" OFF)
    if(ALCP_ENABLE_DEBUG_LOGGING)
        SET(ALCP_ENABLE_DEBUG_LOGGING ON)
    endif()
    
    # Set Build OS
    IF(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
        SET(ALCP_BUILD_OS_LINUX ON)
        SET(ALCP_BUILD_OS_WINDOWS OFF)
    ELSE()
        SET(ALCP_BUILD_OS_LINUX OFF)
        SET(ALCP_BUILD_OS_WINDOWS ON)
    ENDIF(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")

    # Check Endian
    TEST_BIG_ENDIAN(ALCP_CONFIG_LITTLE_ENDIAN)
    INVERTBOOLEAN("ALCP_CONFIG_LITTLE_ENDIAN" ALCP_CONFIG_LITTLE_ENDIAN)

    # Keeping Command line variable same.
    SET(ALCP_ENABLE_AOCL_UTILS ${ENABLE_AOCL_UTILS})

    # The AOCL_ENABLE_INSTRUCTION override exists to exercise kernels that the
    # host CPU would not otherwise select, so it is built only where the tests
    # and benchmarks that use it are built. Derived rather than cached, so that
    # a reconfigure that changes ALCP_ENABLE_TESTS always recomputes it.
    SET(ALCP_ENABLE_INSTRUCTION_OVERRIDE ${ALCP_ENABLE_TESTS})

    # secure_getenv() is a GNU extension: absent on Windows and on musl before
    # 1.1.24. Probing for it rather than assuming keeps those platforms building;
    # they fall back to getenv(), which is what the code did previously.
    CHECK_CXX_SYMBOL_EXISTS(secure_getenv stdlib.h ALCP_HAVE_SECURE_GETENV)

    IF (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        SET(COMPILER_IS_CLANG ON)
    ELSEIF (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        SET(COMPILER_IS_GCC ON)
    ELSEIF (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        SET(COMPILER_IS_MSVC ON)
    ENDIF()

    # Set lib name
    # TODO (Need to find a way to get the bin name from cmake)
    string(TOUPPER "${CMAKE_BUILD_TYPE}" BUILD_TYPE_UPPER)
    IF(ALCP_BUILD_OS_LINUX)
        if(BUILD_TYPE_UPPER STREQUAL "DEBUG")
            SET(ALCP_LIB_OUTPUT_FILE_NAME_STRING "${ALCP_BINARY_DIR}/libalcp_DEBUG.so")
        ELSE()
            SET(ALCP_LIB_OUTPUT_FILE_NAME_STRING "${ALCP_BINARY_DIR}/libalcp.so")
        ENDIF()
    ENDIF(ALCP_BUILD_OS_LINUX)
    IF(ALCP_BUILD_OS_WINDOWS)
        IF(BUILD_TYPE_UPPER STREQUAL "DEBUG")
            SET(ALCP_LIB_OUTPUT_FILE_NAME_STRING "${ALCP_BINARY_DIR}/libalcp_DEBUG.dll")
        ELSE()
            SET(ALCP_LIB_OUTPUT_FILE_NAME_STRING "${ALCP_BINARY_DIR}/libalcp.dll")
        ENDIF()
    ENDIF(ALCP_BUILD_OS_WINDOWS)

    # CONFIGURE A HEADER FILE TO PASS SOME OF THE CMAKE SETTINGS
    # TO THE SOURCE CODE
    # Written into ALCP's own build directory - never the source tree, and
    # never the parent's build root under a unified build. Any generated header
    # shared between build directories lets configuring one of them silently
    # change what another builds.
    IF(ALCP_BUILD_OS_LINUX)
        configure_file(${ALCP_ROOT}/include/alcp/config.h.in ${ALCP_BINARY_DIR}/include/config.h UNIX)
    ENDIF(ALCP_BUILD_OS_LINUX)
    IF(ALCP_BUILD_OS_WINDOWS)
        configure_file(${ALCP_ROOT}/include/alcp/config.h.in ${ALCP_BINARY_DIR}/include/config.h WIN32)
    ENDIF(ALCP_BUILD_OS_WINDOWS)

ENDFUNCTION()
