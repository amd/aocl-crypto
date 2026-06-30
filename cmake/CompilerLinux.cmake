 # Copyright (C) 2022-2026, Advanced Micro Devices. All rights reserved.
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
    # check if cc and cxx version mismatch
    if (NOT ${CMAKE_C_COMPILER_VERSION} STREQUAL ${CMAKE_CXX_COMPILER_VERSION})
        message(FATAL_ERROR "cc and cxx versions are different!")
    endif()
endfunction(alcp_check_compiler_version)


# Generic Warnings
SET (ALCP_WARNINGS -Wall -Werror -Wno-gnu-zero-variadic-macro-arguments -Wno-vla)
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
    add_compile_options(-fmacro-prefix-map=${ALCP_ROOT}=.)
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

# The AVX512 tier (arch_zen4) is, by DEFAULT, pinned to the PORTABLE Zen4-era ISA
# floor (-march=znver3 + explicit AVX512 flags), so the binary is redistributable
# and runs on all Zen4/5/6 (the hot kernels are CPUID-dispatched at runtime, so
# this costs no measurable throughput vs a host-native floor).
#
# If you want the arch_zen4 tier built for the BUILD HOST's own Zen generation
# instead (detected via `gcc -march=native`, capped to compiler support), set
# -DALCP_ARCH_PORTABLE=OFF.
#
option(ALCP_ARCH_PORTABLE "Pin the AVX512 (arch_zen4) tier to the PORTABLE Zen4-era ISA floor (-march=znver3 + explicit AVX512 flags). Use for redistributable binaries." ON)

# ALCP_ARCH_MTUNE flag controlling -mtune for the AVX512 (arch_zen4) tier (scheduling
# only, always ISA-safe). It improves performance in some cases when set to auto.
# Accepted values:
#   ""     (empty, default) -> no -mtune applied
#   auto                    -> latest znver the compiler supports
#   znverN (e.g. znver5)    -> that specific -mtune target
set(ALCP_ARCH_MTUNE "" CACHE STRING "-mtune for the AVX512 (arch_zen4) tier.")

function(alcp_detect_host_znver out_var)
    set(${out_var} "" PARENT_SCOPE)
    # Resolve the effective `-march=native` generation from the compiler's own
    # `__znverN__` macro - works for both GCC and Clang/AOCC.
    execute_process(
        COMMAND ${CMAKE_CXX_COMPILER} -march=native -dM -E -x c++ /dev/null
        OUTPUT_VARIABLE _probe
        ERROR_QUIET)
    string(REGEX MATCH "__(znver[0-9]+)__" _m "${_probe}")
    set(_host "${CMAKE_MATCH_1}")
    if(NOT _host MATCHES "^znver[0-9]+$")
        message(STATUS "alcp_detect_host_znver: host is not a znver target ('${_host}'); leaving -march unset")
        return()
    endif()
    # Cap to what the compiler can actually emit (older compiler on newer HW).
    if(NOT DEFINED COMPILER_SUPPORTS_ZNVER4)
        CHECK_CXX_COMPILER_FLAG("-march=znver4" COMPILER_SUPPORTS_ZNVER4)
        CHECK_CXX_COMPILER_FLAG("-march=znver5" COMPILER_SUPPORTS_ZNVER5)
        CHECK_CXX_COMPILER_FLAG("-march=znver6" COMPILER_SUPPORTS_ZNVER6)
    endif()
    if(_host STREQUAL "znver6" AND NOT COMPILER_SUPPORTS_ZNVER6)
        set(_host znver5)
    endif()
    if(_host STREQUAL "znver5" AND NOT COMPILER_SUPPORTS_ZNVER5)
        set(_host znver4)
    endif()
    set(${out_var} "${_host}" PARENT_SCOPE)
endfunction(alcp_detect_host_znver)

function(alcp_apply_zen4_host_and_mtune list_var)
    set(_flags ${${list_var}})

    if(ALCP_ARCH_PORTABLE)
        message(STATUS "ALCP_ARCH_PORTABLE=ON: arch_zen4 pinned to portable Zen4-era ISA floor (-march=znver3 + AVX512 flags); runs on all Zen4/5/6")
    else()
        alcp_detect_host_znver(_host_znver)
        if(_host_znver)
            message(WARNING "arch_zen4 ISA floor raised to host generation -march=${_host_znver}.")
            list(APPEND _flags -march=${_host_znver})
        else()
            message(STATUS "arch_zen4: host znver not detected; keeping portable Zen4-era floor")
        endif()
    endif()

    # -mtune (scheduling only, ISA-safe) is controlled by ALCP_ARCH_MTUNE.
    # Defaults to OFF (empty); pass explicitly to opt in:
    #   ""     (empty, default) -> no -mtune
    #   auto                    -> latest znver the compiler supports
    #   znverN (e.g. znver5)    -> that specific -mtune target
    if(ALCP_ARCH_MTUNE)
        if(ALCP_ARCH_MTUNE STREQUAL "auto")
            CHECK_CXX_COMPILER_FLAG("-march=znver4" COMPILER_SUPPORTS_ZNVER4)
            CHECK_CXX_COMPILER_FLAG("-march=znver5" COMPILER_SUPPORTS_ZNVER5)
            CHECK_CXX_COMPILER_FLAG("-march=znver6" COMPILER_SUPPORTS_ZNVER6)
            set(_latest_tune "")
            if(COMPILER_SUPPORTS_ZNVER4)
                message(STATUS "Compiler Supports znver4")
                set(_latest_tune znver4)
            endif()
            if(COMPILER_SUPPORTS_ZNVER5)
                message(STATUS "Compiler Supports znver5")
                set(_latest_tune znver5)
            endif()
            if(COMPILER_SUPPORTS_ZNVER6)
                message(STATUS "Compiler Supports znver6")
                set(_latest_tune znver6)
            endif()
        else()
            # Unsupported znver skipped with a warning instead of hard-failing the compile.
            string(MAKE_C_IDENTIFIER "ALCP_MTUNE_OK_${ALCP_ARCH_MTUNE}" _mtune_ok)
            CHECK_CXX_COMPILER_FLAG("-mtune=${ALCP_ARCH_MTUNE}" ${_mtune_ok})
            if(${_mtune_ok})
                set(_latest_tune ${ALCP_ARCH_MTUNE})
            else()
                message(WARNING "ALCP_ARCH_MTUNE='${ALCP_ARCH_MTUNE}' not supported by this compiler; skipping -mtune.")
            endif()
        endif()

        if(_latest_tune)
            message(WARNING "ALCP_ARCH_MTUNE: applying -mtune=${_latest_tune} to arch_zen4 (scheduling only, ISA-safe); see CPUPL-8571.")
            list(APPEND _flags -mtune=${_latest_tune})
        endif()
    endif()

    set(${list_var} ${_flags} PARENT_SCOPE)
endfunction(alcp_apply_zen4_host_and_mtune)

# lib/arch/zen4 Compile Flags
function(alcp_get_arch_cflags_zen4)
    set(ARCH_COMPILE_FLAGS
        -O3 -fPIC -march=znver3 -mavx -mavx2 -maes -mvaes -mpclmul -mavx512f -mavx512dq -mavx512ifma
        -mavx512cd -mavx512bw -mavx512vl -mavx512vbmi -mavx512vbmi2 -mavx512vnni -mavx512bitalg
        -mavx512vpopcntdq -mvpclmulqdq
        CACHE INTERNAL ""
        )

    alcp_apply_zen4_host_and_mtune(ARCH_COMPILE_FLAGS)

    set(ARCH_COMPILE_FLAGS ${ARCH_COMPILE_FLAGS} PARENT_SCOPE)
endfunction(alcp_get_arch_cflags_zen4)


# lib/arch/zen4 Compile Flags
function(alcp_get_arch_cflags_zen4_clang)
    set(ARCH_COMPILE_FLAGS
        -O3 -fPIC -march=znver3 -mavx -mavx2 -maes -mvaes -mpclmul -mavx512f -mavx512dq -mavx512ifma
        -mavx512cd -mavx512bw -mavx512vl -mavx512vbmi -mavx512vbmi2 -mavx512vnni -mavx512bitalg
        -mavx512vpopcntdq -mvpclmulqdq
        CACHE INTERNAL ""
        )

    alcp_apply_zen4_host_and_mtune(ARCH_COMPILE_FLAGS)

    set(ARCH_COMPILE_FLAGS ${ARCH_COMPILE_FLAGS} PARENT_SCOPE)
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

# FIXME: workaround for a clang 21.x AddressSanitizer codegen abort. When
# address+undefined+pointer-subtract instrument the same translation unit at
# -O2 or higher, clang 21.x aborts in the sanitizer pass with a bad-signature
# assertion. Dropping pointer-subtract avoids the abort while keeping the rest
# of the sanitizer set. add_compile_options/add_link_options here apply at the
# CALLING directory's scope, so this disables pointer-subtract only for the
# subtree that invokes it (e.g. tests/, bench/) and leaves lib/examples with
# the full set. Gated to clang [21, 22): it is a no-op on every other compiler
# and self-releases once a clang >= 22 with the upstream codegen fix is used.
# The flags are emitted after the inherited top-level -fsanitize=pointer-subtract
# so last-wins disables it for the calling subtree. The durable fix belongs in
# the compiler, not here.
function(alcp_add_sanitize_workaround_flags)
    if(ALCP_SANITIZE
       AND CMAKE_CXX_COMPILER_ID STREQUAL "Clang"
       AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 21
       AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 22)
        add_compile_options(-fno-sanitize=pointer-subtract)
        add_link_options(-fno-sanitize=pointer-subtract)
    endif()
endfunction(alcp_add_sanitize_workaround_flags)

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
        
        # Add coverage flags to architecture-specific targets
        if(TARGET arch_avx2)
            target_compile_options(arch_avx2 PUBLIC ${ALCP_CFLAGS_COV_GCC})
        endif()
        if(TARGET arch_zen)
            target_compile_options(arch_zen PUBLIC ${ALCP_CFLAGS_COV_GCC})
        endif()
        if(TARGET arch_zen3)
            target_compile_options(arch_zen3 PUBLIC ${ALCP_CFLAGS_COV_GCC})
        endif()
        if(TARGET arch_zen4)
            target_compile_options(arch_zen4 PUBLIC ${ALCP_CFLAGS_COV_GCC})
        endif()
        if(TARGET arch_ref)
            target_compile_options(arch_ref PUBLIC ${ALCP_CFLAGS_COV_GCC})
        endif()
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        # check if lcov is installed
        find_program(LLVM_COV llvm-cov)
        if (NOT LLVM_COV)
            message(FATAL_ERROR "llvm-cov installation not found, coverage build with AOCC/Clang will not work!")
        endif()
        target_compile_options(alcp PUBLIC ${ALCP_CFLAGS_COV_CLANG})
	    target_compile_options(alcp_static PUBLIC ${ALCP_CFLAGS_COV_CLANG})
        target_link_options(alcp PUBLIC ${ALCP_CFLAGS_COV_CLANG})
        target_link_options(alcp_static PUBLIC ${ALCP_CFLAGS_COV_CLANG})
        
        # Add coverage flags to architecture-specific targets
        if(TARGET arch_avx2)
            target_compile_options(arch_avx2 PUBLIC ${ALCP_CFLAGS_COV_CLANG})
        endif()
        if(TARGET arch_zen)
            target_compile_options(arch_zen PUBLIC ${ALCP_CFLAGS_COV_CLANG})
        endif()
        if(TARGET arch_zen3)
            target_compile_options(arch_zen3 PUBLIC ${ALCP_CFLAGS_COV_CLANG})
        endif()
        if(TARGET arch_zen4)
            target_compile_options(arch_zen4 PUBLIC ${ALCP_CFLAGS_COV_CLANG})
        endif()
        if(TARGET arch_ref)
            target_compile_options(arch_ref PUBLIC ${ALCP_CFLAGS_COV_CLANG})
        endif()
    endif()
endfunction(alcp_add_coverage_flags)

# check if 7zip utility is installed
function(check_7zip_installed)
    find_program(7_ZIP 7z)
    if (7_ZIP)
        message(STATUS "7zip is installed: ${7_ZIP}")
    else()
        message(FATAL_ERROR "7zip is not installed, alcp compilation wont work!")
    endif()
endfunction()
