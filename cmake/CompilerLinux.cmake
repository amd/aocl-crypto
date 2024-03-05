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


# get build environment
function(alcp_get_build_environment)
    if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        set (ALCP_BUILD_COMPILER "GCC_v${CMAKE_CXX_COMPILER_VERSION}")
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        set (ALCP_BUILD_COMPILER "Clang_v${CMAKE_CXX_COMPILER_VERSION}")
    endif()

    # uses lsb_release utility on linux, as cmake doesnt have a variable which has the Linux flavor information
    find_program(LSB_RELEASE_EXEC lsb_release)
    if(NOT LSB_RELEASE_EXEC)
        MESSAGE(FATAL_ERROR "LSB Release is missing from the machine, please install lsb_release!")
    endif()
    execute_process(COMMAND ${LSB_RELEASE_EXEC} -r -s
        OUTPUT_VARIABLE OS_VERSION
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    execute_process(COMMAND ${LSB_RELEASE_EXEC} -i -s
        OUTPUT_VARIABLE OS_VENDOR
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    
    # final build env string will contain compiler and system environment details where the binary was created
    set (ALCP_BUILD_ENV ${ALCP_BUILD_COMPILER}_${OS_VENDOR}_${OS_VERSION} PARENT_SCOPE)
endfunction(alcp_get_build_environment)


# check compiler version
function(alcp_check_compiler_version)
    include(CheckCXXCompilerFlag)
    set(GCC_MIN_REQ "10.3.0")
    set (CLANG_MIN_REQ "12.0.0")
    # if gcc
    if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")

        set(CMAKE_COMPILER_IS_GCC ON PARENT_SCOPE)
        string(SUBSTRING ${CMAKE_CXX_COMPILER_VERSION} 0 2 CMAKE_COMPILER_GCC_VERSION)
        set(CMAKE_COMPILER_GCC_VERSION ${CMAKE_COMPILER_GCC_VERSION} PARENT_SCOPE)

        if(${CMAKE_C_COMPILER_VERSION} VERSION_LESS ${GCC_MIN_REQ})
            message(FATAL_ERROR "Using c compiler version ${CMAKE_C_COMPILER_VERSION}, min. reqd version is ${GCC_MIN_REQ}!")
        endif()
        if(${CMAKE_CXX_COMPILER_VERSION} VERSION_LESS ${GCC_MIN_REQ})
            message(FATAL_ERROR "Using c++ compiler version ${CMAKE_CXX_COMPILER_VERSION}, min. reqd version is ${GCC_MIN_REQ}!")
        endif()
    # if aocc/clang
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        set(CMAKE_COMPILER_IS_GCC OFF PARENT_SCOPE)
        if(${CMAKE_C_COMPILER_VERSION} VERSION_LESS ${CLANG_MIN_REQ})
            message(FATAL_ERROR "Using c compiler version ${CMAKE_C_COMPILER_VERSION}, min. reqd version is ${CLANG_MIN_REQ}!")
        endif()
        if(${CMAKE_CXX_COMPILER_VERSION} VERSION_LESS ${CLANG_MIN_REQ})
            message(FATAL_ERROR "Using c++ compiler version ${CMAKE_CXX_COMPILER_VERSION}, min. reqd version is ${CLANG_MIN_REQ}!")
        endif()
    endif()
endfunction(alcp_check_compiler_version)


# Generic Warnings
function(alcp_get_cflags_warnings)
    set(ALCP_CFLAGS_WARNINGS "-Wall" CACHE INTERNAL "")
    set(ALCP_CFLAGS_WARNINGS ${ALCP_CFLAGS_WARNINGS} PARENT_SCOPE)
endfunction(alcp_get_cflags_warnings)

# Generic Release Flags
function(alcp_get_cflags)
    set(ALCP_CFLAGS
        -O2
        -pedantic
        -Werror
        CACHE INTERNAL ""
    )
    set(ALCP_CFLAGS ${ALCP_CFLAGS} PARENT_SCOPE)
endfunction(alcp_get_cflags)

# Generic Debug Flags
function(alcp_get_cflags_debug)
    set(ALCP_CFLAGS_DEBUG
        "-ggdb"
        CACHE INTERNAL ""
        )
    set(ALCP_CFLAGS_DEBUG ${ALCP_CFLAGS_DEBUG} PARENT_SCOPE)
endfunction(alcp_get_cflags_debug)

# Generic Architecture Compile Flags
function(alcp_get_cflags_arch)
    set(ALCP_CFLAGS_ARCH
        ""
        CACHE INTERNAL ""
        )
    set(ALCP_CFLAGS_ARCH ${ALCP_CFLAGS_ARCH} PARENT_SCOPE)
endfunction(alcp_get_cflags_arch)

# Reference Architecture Compile Flags
function(alcp_get_arch_cflags_reference)
    set(ARCH_COMPILE_FLAGS
        -fPIC -O3 -msse2
        CACHE INTERNAL ""
        )
    set(ARCH_COMPILE_FLAGS ${ARCH_COMPILE_FLAGS} PARENT_SCOPE)
endfunction(alcp_get_arch_cflags_reference)

# lib/arch/avx2 Compile Flags
function(alcp_get_arch_cflags_avx2)
    set(ARCH_COMPILE_FLAGS
        -fPIC -msse2 -maes -mavx2 -msha -mno-vaes -mpclmul -mbmi2 -madx
        CACHE INTERNAL ""
        )
    set(ARCH_COMPILE_FLAGS ${ARCH_COMPILE_FLAGS} PARENT_SCOPE)
endfunction(alcp_get_arch_cflags_avx2)

# lib/arch/zen Compile Flags
function(alcp_get_arch_cflags_zen)
    set(ARCH_COMPILE_FLAGS
        -fPIC -march=znver1 -msse2 -maes -mavx2 -msha -mno-vaes -mpclmul
        CACHE INTERNAL ""
        )
    set(ARCH_COMPILE_FLAGS ${ARCH_COMPILE_FLAGS} PARENT_SCOPE)
endfunction(alcp_get_arch_cflags_zen)

# lib/arch/zen3 Compile Flags
function(alcp_get_arch_cflags_zen3)
    set(ARCH_COMPILE_FLAGS
        -O3 -fPIC -march=znver3 -mavx -mavx2 -maes -mvaes -mpclmul -mvpclmulqdq
        CACHE INTERNAL ""
        )
    set(ARCH_COMPILE_FLAGS ${ARCH_COMPILE_FLAGS} PARENT_SCOPE)
endfunction(alcp_get_arch_cflags_zen3)

# lib/arch/zen4 Compile Flags
function(alcp_get_arch_cflags_zen4)
    set(ARCH_COMPILE_FLAGS
        -O3 -fPIC -march=znver3 -mavx -mavx2 -maes -mvaes -mpclmul -mavx512f -mavx512dq -mavx512ifma
        -mavx512cd -mavx512bw -mavx512vl -mavx512vbmi -mavx512vbmi2 -mavx512vnni -mavx512bitalg
        -mavx512vpopcntdq -mvpclmulqdq -DUSE_AVX512
        CACHE INTERNAL ""
        )
    set(ARCH_COMPILE_FLAGS ${ARCH_COMPILE_FLAGS} PARENT_SCOPE)
    # check if compiler supports -march=znver4
    CHECK_CXX_COMPILER_FLAG("-march=znver4" COMPILER_SUPPORTS_ZNVER4)
    if(COMPILER_SUPPORTS_ZNVER4)
      message(STATUS "Compiler Supports znver4")
      set(ARCH_COMPILE_FLAGS ${ARCH_COMPILE_FLAGS} -march=znver4 PARENT_SCOPE)
    endif()
endfunction(alcp_get_arch_cflags_zen4)


# lib/arch/zen4 Compile Flags
function(alcp_get_arch_cflags_zen4_clang)
    set(ARCH_COMPILE_FLAGS
        -O3 -fPIC -march=znver3 -mavx -mavx2 -maes -mvaes -mpclmul -mavx512f -mavx512dq -mavx512ifma
        -mavx512cd -mavx512bw -mavx512vl -mavx512vbmi -mavx512vbmi2 -mavx512vnni -mavx512bitalg
        -mavx512vpopcntdq -mvpclmulqdq -DUSE_AVX512
        CACHE INTERNAL ""
        )
    set(ARCH_COMPILE_FLAGS ${ARCH_COMPILE_FLAGS} PARENT_SCOPE)
endfunction(alcp_get_arch_cflags_zen4_clang)

# misc options
# sanitizer options
function(alcp_add_sanitize_flags)
    # memory sanitizer supported only by clang
    set (ALCP_SANITIZE_OPTIONS_CLANG
            -fsanitize=memory
            -fsanitize-memory-track-origins
            -fPIC
            -fno-omit-frame-pointer
            CACHE INTERNAL ""
        )

    set(ALCP_OPTIONS_SANITIZE
            -fsanitize=address
            -fsanitize=undefined
            -fsanitize=pointer-subtract
            -fsanitize=pointer-compare
            CACHE INTERNAL ""
        )

    # now check compiler and link to asan libs
    add_compile_definitions(ALCP_COMPILE_OPTIONS_SANITIZE)

    if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        link_libraries(asan)
        add_compile_options(${ALCP_OPTIONS_SANITIZE})
        add_link_options(${ALCP_OPTIONS_SANITIZE})
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        add_compile_options(${ALCP_SANITIZE_OPTIONS_CLANG})
        add_link_options(${ALCP_SANITIZE_OPTIONS_CLANG})
    endif()
endfunction(alcp_add_sanitize_flags)

# coverage
function(alcp_add_coverage_flags)
    set(ALCP_CFLAGS_COV
            -O0
            -fprofile-arcs
            -ftest-coverage
            --coverage
            CACHE INTERNAL ""
        )
	    LINK_LIBRARIES(gcov)
	    ADD_COMPILE_OPTIONS(${ALCP_CFLAGS_COV})
endfunction(alcp_add_coverage_flags)