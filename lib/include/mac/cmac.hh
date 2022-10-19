#include "alcp/alcp.h"
#include "mac.hh"

namespace alcp::mac {
class Cmac final : public Mac
{
  public:
    Cmac();
    Cmac(const alc_mac_info_t& rMacInfo, const alc_key_info_t& keyInfo);
    ~Cmac();
    alc_error_t update(const Uint8* pMsgBuf, Uint64 size) override;
    void        finish() override;
    void        reset() override;
    alc_error_t finalize(const Uint8* pMsgBuf, Uint64 size) override;
};
} // namespace alcp::mac