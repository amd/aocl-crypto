 # Copyright (C) 2022-2025, Advanced Micro Devices. All rights reserved.
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

    cmake_host_system_information(RESULT OS_VERSION QUERY DISTRIB_PRETTY_NAME)
    message(STATUS "OS Information: ${OS_VERSION}")

    # final build env string will contain compiler and system environment details where the binary was created
    set (ALCP_BUILD_ENV ${ALCP_BUILD_COMPILER}_${OS_VERSION} PARENT_SCOPE)
endfunction(alcp_get_build_environment)


# check compiler version
function(alcp_check_compiler_version)
    include(CheckCXXCompilerFlag)
    set(GCC_MIN_REQ "11.3.0")
    set (CLANG_MIN_REQ "14.0.0")
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
SET (ALCP_WARNINGS -Wall -Werror -Wno-gnu-zero-variadic-macro-arguments)
function(alcp_get_cflags_warnings)
    set(ALCP_CFLAGS_WARNINGS ${ALCP_WARNINGS} CACHE INTERNAL "")
    set(ALCP_CFLAGS_WARNINGS ${ALCP_CFLAGS_WARNINGS} PARENT_SCOPE)
endfunction(alcp_get_cflags_warnings)

# Generic Release Flags
function(alcp_get_cflags)
    set(ALCP_CFLAGS
        -O2
        -pedantic
        ${ALCP_WARNINGS}
        CACHE INTERNAL ""
    )
    # this is to obfuscate the source paths in the binary
    add_compile_options(-fmacro-prefix-map=${CMAKE_SOURCE_DIR}=.)
    set(ALCP_CFLAGS ${ALCP_CFLAGS} PARENT_SCOPE)
endfunction(alcp_get_cflags)

# Generic Debug Flags
function(alcp_get_cflags_debug)
    set(ALCP_CFLAGS_DEBUG
        -g3 -ggdb -O0
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
# FIXME: this function name has to change
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
    # check if compiler supports -march=znver5
    CHECK_CXX_COMPILER_FLAG("-march=znver5" COMPILER_SUPPORTS_ZNVER5)
    if(COMPILER_SUPPORTS_ZNVER5)
      message(STATUS "Compiler Supports znver5")
      set(ARCH_COMPILE_FLAGS ${ARCH_COMPILE_FLAGS} -march=znver5 PARENT_SCOPE)
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

    # check if compiler supports -march=znver4 for AOCC
    if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        CHECK_CXX_COMPILER_FLAG("-march=znver4" COMPILER_SUPPORTS_ZNVER4)
        if(COMPILER_SUPPORTS_ZNVER4)
            message(STATUS "Compiler Supports znver4")
            set(ARCH_COMPILE_FLAGS ${ARCH_COMPILE_FLAGS} -march=znver4 PARENT_SCOPE)
        endif()
        # check if compiler supports -march=znver5
        CHECK_CXX_COMPILER_FLAG("-march=znver5" COMPILER_SUPPORTS_ZNVER5)
        if(COMPILER_SUPPORTS_ZNVER5)
            message(STATUS "Compiler Supports znver5")
            set(ARCH_COMPILE_FLAGS ${ARCH_COMPILE_FLAGS} -march=znver5 PARENT_SCOPE)
        endif()
    endif()

endfunction(alcp_get_arch_cflags_zen4_clang)

# misc options
# sanitizer options
function(alcp_add_sanitize_flags)
    # memory sanitizer supported only by clang
    # FIXME: since memsan is not supported by all the dependency libraries,
    # compilation is disabled with memsan.
    set (ALCP_OPTIONS_SANITIZE
            #-fsanitize=memory
            #-fsanitize-memory-track-origins
            -fsanitize=address,undefined
            -fno-sanitize=vptr
            -fsanitize=pointer-subtract
            -fsanitize=pointer-compare
            -fPIC
            -fno-omit-frame-pointer
            CACHE INTERNAL ""
        )

    # if gcc, link to libasan
    if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        link_libraries(asan)
    endif()
    add_compile_options(${ALCP_OPTIONS_SANITIZE})
    add_link_options(${ALCP_OPTIONS_SANITIZE})
endfunction(alcp_add_sanitize_flags)

# coverage flags
function(alcp_add_coverage_flags)
    # coverage flags supported by gcc
    set(ALCP_CFLAGS_COV_GCC
            -O0
            -fprofile-arcs
            -ftest-coverage
            CACHE INTERNAL ""
    )
    #link flags
    set(ALCP_LFLAGS_COV_GCC
            --coverage
            -lgcov
            CACHE INTERNAL ""
    )
    # coverage flags supported by clang compiler
    set(ALCP_CFLAGS_COV_CLANG
            -g
            -O0
            -fprofile-instr-generate
            -fcoverage-mapping
            CACHE INTERNAL ""
    )
    if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        # check if lcov is installed
        find_program(LCOV lcov)
        if (NOT LCOV)
            message(FATAL_ERROR "lcov installation not found, coverage build with gcc will not work!")
        endif()
	    target_compile_options(alcp PUBLIC ${ALCP_CFLAGS_COV_GCC})
	    target_compile_options(alcp_static PUBLIC ${ALCP_CFLAGS_COV_GCC})
        target_link_options(alcp PUBLIC ${ALCP_LFLAGS_COV_GCC})
        target_link_options(alcp_static PUBLIC ${ALCP_LFLAGS_COV_GCC})
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        # check if lcov is installed
        find_program(LLVM_COV llvm-cov-14)
        if (NOT LLVM_COV)
            message(FATAL_ERROR "llvm-cov installation not found, coverage build with AOCC/Clang will not work!")
        endif()
        target_compile_options(alcp PUBLIC ${ALCP_CFLAGS_COV_CLANG})
	    target_compile_options(alcp_static PUBLIC ${ALCP_CFLAGS_COV_CLANG})
        target_link_options(alcp PUBLIC ${ALCP_CFLAGS_COV_CLANG})
        target_link_options(alcp_static PUBLIC ${ALCP_CFLAGS_COV_CLANG})
    endif()
endfunction(alcp_add_coverage_flags)