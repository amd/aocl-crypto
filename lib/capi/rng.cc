#include "rng.hh"
#include "alcp/macros.h"
#include "error.hh"
#include <iostream>
#include <stdio.h>

EXTERN_C_BEGIN
uint64_t
alcp_rng_context_size(const alc_rng_info_t rng_info)
{
    uint64_t size = sizeof(alc_rng_handle_t);
    return size;
}
alc_error_t
alcp_rng_supported(const alc_rng_info_t* tt)
{
    alc_error_t error = ALC_ERROR_NOT_SUPPORTED;

    switch (tt->r_type) {
        case ALC_RNG_TYPE_DESCRETE:
            switch (tt->r_distrib) {
                case ALC_RNG_DISTRIB_UNIFORM:
                    switch (tt->r_source) {
                        case ALC_RNG_SOURCE_OS:
                            error = ALC_ERROR_NONE;
                            break;
                        case ALC_RNG_SOURCE_ARCH:
                            error = ALC_ERROR_NONE;
                            break;
                    }
            }
    }

    return error;
}

alc_error_t
alcp_rng_request(const alc_rng_info_t* tt, alc_rng_handle_t* ctx)
{
    alc_error_t       error = ALC_ERROR_NOT_SUPPORTED;
    alcp::rng_Handle* cntxt = new alcp::rng_Handle;
    ctx->ctx                = cntxt;
    switch (tt->r_type) {
        case ALC_RNG_TYPE_DESCRETE:
            switch (tt->r_distrib) {
                case ALC_RNG_DISTRIB_UNIFORM:
                    error = ALC_ERROR_NONE;
                    switch (tt->r_source) {
                        case ALC_RNG_SOURCE_OS:
                            cntxt->rng_info.r_distrib = tt->r_distrib;
                            cntxt->rng_info.r_type    = tt->r_type;
                            cntxt->rng_info.r_source  = tt->r_source;
                            cntxt->rng_info.r_flags   = tt->r_flags;
                            cntxt->exec               = new alcp::rng::OsRng();
                            // cntxt->engine =
                            // &(alcp::rng::rng_engine_linux_urandom);
                            break;
                        case ALC_RNG_SOURCE_ARCH:
                            cntxt->rng_info.r_distrib = tt->r_distrib;
                            cntxt->rng_info.r_type    = tt->r_type;
                            cntxt->rng_info.r_source  = tt->r_source;
                            cntxt->rng_info.r_flags   = tt->r_flags;
                            cntxt->exec = new alcp::rng::ArchRng();
                            // cntxt->engine =
                            // &(alcp::rng::rng_engine_amd_rdrand_bytes);
                            break;
                        default:
                            error = ALC_ERROR_NOT_SUPPORTED;
                    }
            }
    }
    return error;
}

alc_error_t
alcp_rng_gen_random(alc_rng_handle_t* tt,
                    uint8_t*          buf, /* RNG output buffer */
                    uint64_t          size /* output buffer size */
)
{
    alcp::rng_Handle* cntxt = (alcp::rng_Handle*)tt->ctx;
    uint64_t          randn = 0;
    int               tries = 10;
    if (buf == NULL) {
        return ALC_ERROR_INVALID_ARG;
    }
    while (randn != size) {
        randn += cntxt->exec->engineDefault(buf + randn, size - randn);
        tries -= 1;
        if (tries == 0) {
            return ALC_ERROR_NO_ENTROPY;
        }
    }
    return ALC_ERROR_NONE;
}

alc_error_t
alcp_rng_finish(alc_rng_handle_t* tt)
{
    alcp::rng_Handle* cntxt = (alcp::rng_Handle*)tt->ctx;
    delete cntxt->exec;
    delete cntxt;
    return ALC_ERROR_NONE;
}

EXTERN_C_END
