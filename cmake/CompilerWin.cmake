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
    set(OS_VERSION ${CMAKE_HOST_SYSTEM})
    set (ALCP_BUILD_ENV ${ALCP_BUILD_COMPILER}_${OS_VERSION} PARENT_SCOPE)
endfunction(alcp_get_build_environment)


# check compiler version
function(alcp_check_compiler_version)
    set(CLANG_MIN_REQ "12.0.0")
	if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
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
    set(ALCP_CFLAGS_WARNINGS /W4 -Wpedantic -Wno-unused-parameter CACHE INTERNAL "")
    set(ALCP_CFLAGS_WARNINGS ${ALCP_CFLAGS_WARNINGS} PARENT_SCOPE)
endfunction(alcp_get_cflags_warnings)

# Generic Release Flags
function(alcp_get_cflags)
    set(ALCP_CFLAGS
        /O2
        /W4
        /WX
        CACHE INTERNAL ""
    )
    set(ALCP_CFLAGS ${ALCP_CFLAGS} PARENT_SCOPE)
endfunction(alcp_get_cflags)

# Generic Debug Flags
function(alcp_get_cflags_debug)
    set(ALCP_CFLAGS_DEBUG
        ""
        CACHE INTERNAL ""
    )
    set(ALCP_CFLAGS_DEBUG ${ALCP_CFLAGS_DEBUG} PARENT_SCOPE)
endfunction(alcp_get_cflags_debug)

# Generic Architecture Compile Flags
function(alcp_get_cflags_arch)
    set(ALCP_CFLAGS_ARCH
        "/arch:AVX2"
        CACHE INTERNAL "")
    set(ALCP_CFLAGS_ARCH ${ALCP_CFLAGS_ARCH} PARENT_SCOPE)
endfunction(alcp_get_cflags_arch)

# Reference Architecture Compile Flags
function(alcp_get_arch_cflags_reference)
    set(ARCH_COMPILE_FLAGS
        /Ox -msse2
        CACHE INTERNAL ""
        )
    set(ARCH_COMPILE_FLAGS ${ARCH_COMPILE_FLAGS} PARENT_SCOPE)
endfunction(alcp_get_arch_cflags_reference)

# lib/arch/avx2 Compile Flags
function(alcp_get_arch_cflags_avx2)
    set(ARCH_COMPILE_FLAGS
        -msse2 -maes -mavx2 -msha -mno-vaes -mpclmul -madx
        CACHE INTERNAL ""
    )
    set(ARCH_COMPILE_FLAGS ${ARCH_COMPILE_FLAGS} PARENT_SCOPE)
endfunction(alcp_get_arch_cflags_avx2)

# lib/arch/zen Compile Flags
function(alcp_get_arch_cflags_zen)
    set(ARCH_COMPILE_FLAGS
        -msse2 -maes -mavx2 -msha -mno-vaes -mpclmul -madx
        CACHE INTERNAL ""
        )
    set(ARCH_COMPILE_FLAGS ${ARCH_COMPILE_FLAGS} PARENT_SCOPE)
endfunction(alcp_get_arch_cflags_zen)

# lib/arch/zen3 Compile Flags
function(alcp_get_arch_cflags_zen3)
    set(ARCH_COMPILE_FLAGS
        -mavx -mavx2 -maes -mvaes -mpclmul -mvpclmulqdq -madx /arch:AVX2
        CACHE INTERNAL ""
        )
    set(ARCH_COMPILE_FLAGS ${ARCH_COMPILE_FLAGS} PARENT_SCOPE)
endfunction(alcp_get_arch_cflags_zen3)

# lib/arch/zen4 Compile Flags
function(alcp_get_arch_cflags_zen4)
    set(ARCH_COMPILE_FLAGS
        /Ox -mavx -mavx2 -maes -mvaes -mpclmul -mvpclmulqdq -mavx512ifma -DUSE_AVX512 /arch:AVX512
        CACHE INTERNAL ""
        )
    set(ARCH_COMPILE_FLAGS ${ARCH_COMPILE_FLAGS} PARENT_SCOPE)
endfunction(alcp_get_arch_cflags_zen4)

# lib/arch/zen4 Compile Flags
function(alcp_get_arch_cflags_zen4_clang)
    set(ARCH_COMPILE_FLAGS
        /Ox -mavx -mavx2 -maes -mvaes -mpclmul -mvpclmulqdq -mavx512ifma -DUSE_AVX512 /arch:AVX512
        CACHE INTERNAL ""
        )
    set(ARCH_COMPILE_FLAGS ${ARCH_COMPILE_FLAGS} PARENT_SCOPE)
endfunction(alcp_get_arch_cflags_zen4_clang)



# if address sanitizer used
function(alcp_add_sanitize_flags)
    set(ALCP_OPTIONS_SANITIZE
            -fsanitize=address
            -fsanitize=undefined
            -fsanitize=nullability
            CACHE INTERNAL ""
        )
    link_libraries(clang_rt.asan_dynamic-x86_64)
    add_compile_options(${ALCP_OPTIONS_SANITIZE} -fno-sanitize=address /Zi /Od)
endfunction(alcp_add_sanitize_flags)

#coverage
function(alcp_add_coverage_flags)
    set(ALCP_CFLAGS_COV
            --coverage
            CACHE INTERNAL ""
        )
    link_libraries(clang_rt.profile-x86_64.lib)
    set(CMAKE_CXX_OUTPUT_EXTENSION_REPLACE ON)
    add_compile_options(${ALCP_CFLAGS_COV} /Od)
endfunction(alcp_add_coverage_flags)