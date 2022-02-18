#include "rng.hh"
#include "alcp/macros.h"
#include "error.hh"
#include <iostream>
#include <stdio.h>

EXTERN_C_BEGIN uint64_t
alcp_rng_context_size(const alc_rng_info_t rng_info)
{
    uint64_t size = sizeof(alcp::rng_Handle);
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
    alc_error_t error = ALC_ERROR_NOT_SUPPORTED;
    /*
     * TODO: Move this to builder, find a way to check support without redundant
     * code
     */
    switch (tt->r_type) {
        case ALC_RNG_TYPE_DESCRETE:
            switch (tt->r_distrib) {
                case ALC_RNG_DISTRIB_UNIFORM:
                    error = ALC_ERROR_NONE;
                    alcp::rng::RngBuilder::Build(
                        tt, static_cast<alcp::rng_Handle*>(ctx->context));
                    break;
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
    alcp::rng_Handle* cntxt = (alcp::rng_Handle*)tt->context;
    uint64_t          randn = 0;
    int               tries = 10;
    if (buf == NULL) {
        return ALC_ERROR_INVALID_ARG;
    }
    randn += cntxt->read_random(cntxt->m_rng, buf, size);
    return ALC_ERROR_NONE;
}

alc_error_t
alcp_rng_finish(alc_rng_handle_t* tt)
{
    delete ((static_cast<alcp::rng_Handle*>(tt->context))->m_rng);
    return ALC_ERROR_NONE;
}

EXTERN_C_END
