#include "alcp/alcp.h"
#include "mac.hh"

namespace alcp::mac {
class Hmac final : public Mac
{
  public:
    Hmac();
    Hmac(const alc_mac_info_t& rMacInfo, const alc_key_info_t& keyInfo);
    ~Hmac();
    // alcp::digest::Digest m_hash;
    alc_error_t update(const Uint8* pMsgBuf, Uint64 size) override;
    void        finish() override;
    void        reset() override;
    alc_error_t finalize(const Uint8* pMsgBuf, Uint64 size) override;
    alc_error_t copyHash(Uint8* pHashBuf, Uint64 size) const;
};
} // namespace alcp::mac