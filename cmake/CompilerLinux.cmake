 # Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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

# check compiler version
function(alcp_check_compiler_version)
    set(GCC_MIN_REQ "10.3.0")
    set (CLANG_MIN_REQ "12.0.0")
    # if gcc
    if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        if(${CMAKE_C_COMPILER_VERSION} VERSION_LESS ${GCC_MIN_REQ})
            message(FATAL_ERROR "Using c compiler version ${CMAKE_C_COMPILER_VERSION}, min. reqd version is ${GCC_MIN_REQ}!")
        endif()
        if(${CMAKE_CXX_COMPILER_VERSION} VERSION_LESS ${GCC_MIN_REQ})
            message(FATAL_ERROR "Using c++ compiler version ${CMAKE_CXX_COMPILER_VERSION}, min. reqd version is ${GCC_MIN_REQ}!")
        endif()
    # if aocc/clang
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        if(${CMAKE_C_COMPILER_VERSION} VERSION_LESS ${CLANG_MIN_REQ})
            message(FATAL_ERROR "Using c compiler version ${CMAKE_C_COMPILER_VERSION}, min. reqd version is ${CLANG_MIN_REQ}!")
        endif()
        if(${CMAKE_CXX_COMPILER_VERSION} VERSION_LESS ${CLANG_MIN_REQ})
            message(FATAL_ERROR "Using c++ compiler version ${CMAKE_CXX_COMPILER_VERSION}, min. reqd version is ${CLANG_MIN_REQ}!")
        endif()
    endif()
endfunction(alcp_check_compiler_version)

# check min required cmake version
#FIXME: should this be same for windows as well?
function(alcp_check_cmake_version)
    set(CMAKE_MIN_REQ "3.1.0")
    if(${CMAKE_VERSION} VERSION_LESS ${CMAKE_MIN_REQ})
        message(FATAL_ERROR "CMake version detected: ${CMAKE_VERSION}, min. reqd. version is ${CMAKE_MIN_REQ}!")
    endif()
endfunction(alcp_check_cmake_version)

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

# lib/arch/avx2 Compile Flags
function(alcp_get_arch_cflags_avx2)
    set(ARCH_COMPILE_FLAGS 
        -fPIC -msse2 -maes -mavx2 -msha -mno-vaes -mpclmul
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
        -fPIC -march=znver3 -mavx -mavx2 -maes -mvaes -mpclmul -mvpclmulqdq
        CACHE INTERNAL ""
        )
    set(ARCH_COMPILE_FLAGS ${ARCH_COMPILE_FLAGS} PARENT_SCOPE)
endfunction(alcp_get_arch_cflags_zen3)

# lib/arch/zen4 Compile Flags
function(alcp_get_arch_cflags_zen4)
    set(ARCH_COMPILE_FLAGS 
        -fPIC -march=znver3 -mavx -mavx2 -maes -mvaes -mpclmul -mavx512f -mavx512dq -mavx512ifma 
        -mavx512cd -mavx512bw -mavx512vl -mavx512vbmi -mavx512vbmi2 -mavx512vnni -mavx512bitalg 
        -mavx512vpopcntdq -mvpclmulqdq -DUSE_AVX512
        CACHE INTERNAL ""
        )
    set(ARCH_COMPILE_FLAGS ${ARCH_COMPILE_FLAGS} PARENT_SCOPE)
endfunction(alcp_get_arch_cflags_zen4)

# misc options
# TO DO: 
# these sanitizer options are currently defined for gcc
# Maybe different for clang!!

# if address sanitizer used
function(alcp_add_sanitize_flags)
    set(ALCP_OPTIONS_SANITIZE
            -fsanitize=address 
            -fsanitize=undefined 
            -fsanitize=pointer-subtract 
            -fsanitize=pointer-compare 
            CACHE INTERNAL ""
        )
    link_libraries(asan)
    add_compile_options(${ALCP_OPTIONS_SANITIZE})
    add_link_options(${ALCP_OPTIONS_SANITIZE})
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