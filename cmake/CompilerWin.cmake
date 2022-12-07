function(alcp_get_cflags_warnings)
    set(ALCP_CFLAGS_WARNINGS  "/W4" CACHE INTERNAL "")
    set(ALCP_CFLAGS_WARNINGS ${ALCP_CFLAGS_WARNINGS} PARENT_SCOPE)
endfunction(alcp_get_cflags_warnings)

function(alcp_get_cflags)
    set(ALCP_CFLAGS
        /O2
        /W4
        /WX-
        CACHE INTERNAL ""
    )
    set(ALCP_CFLAGS ${ALCP_CFLAGS} PARENT_SCOPE)
endfunction(alcp_get_cflags)

function(alcp_get_cflags_debug)
    set(ALCP_CFLAGS_DEBUG
        ""
        CACHE INTERNAL ""
    )
    set(ALCP_CFLAGS_DEBUG ${ALCP_CFLAGS_DEBUG} PARENT_SCOPE)
endfunction(alcp_get_cflags_debug)

function(alcp_get_cflags_arch)
    set(ALCP_CFLAGS_ARCH
        "/arch:AVX2"
        CACHE INTERNAL "")
    set(ALCP_CFLAGS_ARCH ${ALCP_CFLAGS_ARCH} PARENT_SCOPE)
endfunction(alcp_get_cflags_arch)
