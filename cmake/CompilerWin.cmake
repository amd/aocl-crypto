

# check compiler version
function(alcp_check_compiler_version)
    set(CLANG_MIN_REQ "x.x.x")
    # FIXME set and add min version checks for clang / msvc compilers
endfunction(alcp_check_compiler_version)

# Generic Warnings
function(alcp_get_cflags_warnings)
    set(ALCP_CFLAGS_WARNINGS  "/W4" CACHE INTERNAL "")
    set(ALCP_CFLAGS_WARNINGS ${ALCP_CFLAGS_WARNINGS} PARENT_SCOPE)
endfunction(alcp_get_cflags_warnings)

# Generic Release Flags
function(alcp_get_cflags)
    set(ALCP_CFLAGS
        /O2
        /W4
        /WX-
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

# lib/arch/avx2 Compile Flags
function(alcp_get_arch_cflags_avx2)
    set(ARCH_COMPILE_FLAGS 
        -msse2 -maes -mavx2 -msha -mno-vaes -mpclmul
        CACHE INTERNAL ""
        )
    set(ARCH_COMPILE_FLAGS ${ARCH_COMPILE_FLAGS} PARENT_SCOPE)
endfunction(alcp_get_arch_cflags_avx2)

# lib/arch/zen3 Compile Flags
function(alcp_get_arch_cflags_zen3)
    set(ARCH_COMPILE_FLAGS 
        -mavx -mavx2 -maes -mvaes -mpclmul -mvpclmulqdq /arch:AVX2
        CACHE INTERNAL ""
        )
    set(ARCH_COMPILE_FLAGS ${ARCH_COMPILE_FLAGS} PARENT_SCOPE)
endfunction(alcp_get_arch_cflags_zen3)

# lib/arch/zen4 Compile Flags
function(alcp_get_arch_cflags_zen4)
    set(ARCH_COMPILE_FLAGS 
        -mavx -mavx2 -maes -mvaes -mpclmul -mvpclmulqdq -DUSE_AVX512 /arch:AVX512
        CACHE INTERNAL ""
        )
    set(ARCH_COMPILE_FLAGS ${ARCH_COMPILE_FLAGS} PARENT_SCOPE)
endfunction(alcp_get_arch_cflags_zen4)