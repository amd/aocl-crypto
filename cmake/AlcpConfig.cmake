# Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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

FUNCTION(GEN_CONF)
    # Set ALCP Release Version String
    STRING(TIMESTAMP ALCP_RELEASE_VERSION_STRING "AOCL-Crypto ${AOCL_RELEASE_VERSION} Build %Y%m%d")

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

    IF (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        SET(COMPILER_IS_CLANG ON)
    ELSEIF (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        SET(COMPILER_IS_GCC ON)
    ELSEIF (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        SET(COMPILER_IS_MSVC ON)
    ENDIF()

    # Set lib name
    # TODO (Need to find a way to get the bin name from cmake)
    IF(ALCP_BUILD_OS_LINUX)
        IF(CMAKE_BUILD_TYPE STREQUAL "Debug" OR "DEBUG")
            SET(ALCP_LIB_OUTPUT_FILE_NAME_STRING "${ALCP_BINARY_DIR}/libalcp_DEBUG.so")
        ELSE()
            SET(ALCP_LIB_OUTPUT_FILE_NAME_STRING "${ALCP_BINARY_DIR}/libalcp.so")
        ENDIF()
    ENDIF(ALCP_BUILD_OS_LINUX)
    IF(ALCP_BUILD_OS_WINDOWS)
        IF(CMAKE_BUILD_TYPE STREQUAL "Debug" OR "DEBUG")
            SET(ALCP_LIB_OUTPUT_FILE_NAME_STRING "${ALCP_BINARY_DIR}/libalcp_DEBUG.dll")
        ELSE()
            SET(ALCP_LIB_OUTPUT_FILE_NAME_STRING "${ALCP_BINARY_DIR}/libalcp.dll")
        ENDIF()
    ENDIF(ALCP_BUILD_OS_WINDOWS)


    # CPUID OVERRIDE FLAGS
    IF(ALCP_CPUID_FORCE)
        IF(${ALCP_CPUID_FORCE} STREQUAL "ZEN")
            SET(ALCP_CPUID_DISABLE_AVX512 ON)
            SET(ALCP_CPUID_DISABLE_VAES ON)
            SET(ALCP_CPUID_FORCE_ZEN ON)
        ELSEIF(${ALCP_CPUID_FORCE} STREQUAL "ZEN2")
            SET(ALCP_CPUID_DISABLE_AVX512 ON)
            SET(ALCP_CPUID_DISABLE_VAES ON)
            SET(ALCP_CPUID_FORCE_ZEN2 ON)
        ELSEIF(${ALCP_CPUID_FORCE} STREQUAL "ZEN3")
            SET(ALCP_CPUID_DISABLE_AVX512 ON)
            SET(ALCP_CPUID_FORCE_ZEN3 ON)
        ELSEIF(${ALCP_CPUID_FORCE} STREQUAL "ZEN4")
            SET(ALCP_CPUID_DISABLE_ZEN ON)
            SET(ALCP_CPUID_FORCE_ZEN4 ON)
         ELSEIF(${ALCP_CPUID_FORCE} STREQUAL "ZEN5")
            SET(ALCP_CPUID_DISABLE_ZEN ON)
            SET(ALCP_CPUID_FORCE_ZEN5 ON)
        ENDIF()
    ENDIF(ALCP_CPUID_FORCE)

    # CONFIGURE A HEADER FILE TO PASS SOME OF THE CMAKE SETTINGS
    # TO THE SOURCE CODE
    IF(ALCP_BUILD_OS_LINUX)
        configure_file(${CMAKE_SOURCE_DIR}/include/alcp/config.h.in ${CMAKE_SOURCE_DIR}/include/config.h UNIX)
    ENDIF(ALCP_BUILD_OS_LINUX)
    IF(ALCP_BUILD_OS_WINDOWS)
        configure_file(${CMAKE_SOURCE_DIR}/include/alcp/config.h.in ${CMAKE_SOURCE_DIR}/include/config.h WIN32)
    ENDIF(ALCP_BUILD_OS_WINDOWS)

ENDFUNCTION()
