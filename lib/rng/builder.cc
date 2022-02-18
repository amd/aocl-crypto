#include "alcp/error.h"
#include "rng.hh"

namespace alcp::rng {
template<typename RNGTYPE>
static alc_error_t
__read_random_wrapper(void* pRng, uint8_t* buffer, int buffersize)
{
    int         randn = 0;  // Index location free in buffer
    int         tries = 10; // N tries before giving up
    alc_error_t e     = ALC_ERROR_NONE;
    auto        ap    = static_cast<RNGTYPE*>(pRng);
    while (randn != buffersize) {
        randn += ap->engineDefault(buffer + randn, buffersize - randn);
        tries -= 1;
        if (tries == 0) {
            e = ALC_ERROR_NO_ENTROPY;
            break;
        }
    }
    return e;
}

template<typename SOURCENAME>
static alc_error_t
__build_rng(const alc_rng_info_t* tt, rng_Handle* ctx)
{
    alc_error_t e      = ALC_ERROR_NONE;
    auto        source = new SOURCENAME();
    ctx->m_rng         = static_cast<void*>(source);
    ctx->read_random   = __read_random_wrapper<SOURCENAME>;
    // Add finish also some time later may be

    return e;
}
namespace RngBuilder {
    alc_error_t Build(const alc_rng_info_t* tt, rng_Handle* ctx)
    {
        alc_error_t e           = ALC_ERROR_NONE;
        ctx->rng_info.r_distrib = tt->r_distrib;
        ctx->rng_info.r_type    = tt->r_type;
        ctx->rng_info.r_source  = tt->r_source;
        ctx->rng_info.r_flags   = tt->r_flags;
        switch (tt->r_source) {
            case ALC_RNG_SOURCE_OS:
                __build_rng<OsRng>(tt, ctx);
                break;
            case ALC_RNG_SOURCE_ARCH:
                __build_rng<ArchRng>(tt, ctx);
                break;
            default:
                e = ALC_ERROR_NOT_SUPPORTED;
                break;
        }
        return e;
    }
} // namespace RngBuilder
} // namespace alcp::rng