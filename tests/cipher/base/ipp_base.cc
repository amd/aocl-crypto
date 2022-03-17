#include "ipp_base.hh"

namespace alcp::testing {
IPPCipherBase::IPPCipherBase(const alc_aes_mode_t mode, const uint8_t* iv)
    : m_mode{ mode }
    , m_iv{ iv }
{}

IPPCipherBase::IPPCipherBase(const alc_aes_mode_t mode,
                             const uint8_t*       iv,
                             const uint8_t*       key,
                             const uint32_t       key_len)
    : m_mode{ mode }
    , m_iv{ iv }
    , m_key{ key }
    , m_key_len{ key_len }
{

    IppStatus status = ippStsNoErr;
    status           = ippsAESGetSize(&m_ctxSize);
    m_ctx            = (IppsAESSpec*)(new Ipp8u[m_ctxSize]);
    status           = ippsAESInit(key, key_len, m_ctx, m_ctxSize);
}

IPPCipherBase::~IPPCipherBase()
{
    if (m_ctx != nullptr) {
        delete[](Ipp8u*) m_ctx;
    }
}
bool
IPPCipherBase::init(const uint8_t* iv,
                    const uint8_t* key,
                    const uint32_t key_len)
{
    m_iv = iv;
    return init(key, key_len);
}

bool
IPPCipherBase::init(const uint8_t* key, const uint32_t key_len)
{
    m_key            = key;
    m_key_len        = key_len;
    IppStatus status = ippStsNoErr;
    status           = ippsAESGetSize(&m_ctxSize);
    if (m_ctx != nullptr) {
        delete[](Ipp8u*) m_ctx;
        ;
    }
    m_ctx  = (IppsAESSpec*)(new Ipp8u[m_ctxSize]);
    status = ippsAESInit(key, key_len / 8, m_ctx, m_ctxSize);
    return true;
}

bool
IPPCipherBase::alcpModeToFuncCall(const uint8_t* in,
                                  uint8_t*       out,
                                  int            len,
                                  bool           enc)
{
    IppStatus status = ippStsNoErr;
    uint8_t   iv[16];
    memcpy(iv, m_iv, 16);
    switch (m_mode) {
        case ALC_AES_MODE_CBC:
            if (enc) {
                status = ippsAESEncryptCBC(in, out, len, m_ctx, iv);
            } else {
                status = ippsAESDecryptCBC(in, out, len, m_ctx, iv);
            }
            break;
        case ALC_AES_MODE_CFB:
            if (enc) {
                status = ippsAESEncryptCFB(in, out, len, 16, m_ctx, iv);
            } else {
                status = ippsAESDecryptCFB(in, out, len, 16, m_ctx, iv);
            }
            break;
        case ALC_AES_MODE_OFB:
            if (enc) {
                status = ippsAESEncryptOFB(in, out, len, 16, m_ctx, iv);
            } else {
                status = ippsAESDecryptOFB(in, out, len, 16, m_ctx, iv);
            }
            break;
        case ALC_AES_MODE_CTR:
            if (enc) {
                status = ippsAESEncryptCTR(in, out, len, m_ctx, iv, 128);
            } else {
                status = ippsAESDecryptCTR(in, out, len, m_ctx, iv, 128);
            }
            break;
        default:
            return false;
    }
    return true;
}

bool
IPPCipherBase::encrypt(const uint8_t* plaintxt,
                       const int      len,
                       uint8_t*       ciphertxt)
{
    alcpModeToFuncCall(plaintxt, ciphertxt, len, true);
    return true;
}

bool
IPPCipherBase::decrypt(const uint8_t* ciphertxt,
                       const int      len,
                       uint8_t*       plaintxt)
{
    alcpModeToFuncCall(ciphertxt, plaintxt, len, false);
    return true;
}

} // namespace alcp::testing