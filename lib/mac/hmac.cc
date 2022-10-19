#include "mac/hmac.hh"
namespace alcp::mac {
alc_error_t
Hmac::update(const Uint8* pMsgBuf, Uint64 size)
{
    return ALC_ERROR_NONE;
}

void
Hmac::finish()
{}
void
Hmac::reset()
{}
alc_error_t
Hmac::finalize(const Uint8* pMsgBuf, Uint64 size)
{
    return ALC_ERROR_NONE;
}
alc_error_t
Hmac::copyHash(Uint8* pHashBuf, Uint64 size) const
{
    return ALC_ERROR_NONE;
}

} // namespace alcp::mac