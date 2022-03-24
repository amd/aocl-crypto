#include "base.hh"
#include <alcp/alcp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#pragma once
namespace alcp::testing {
class OpenSSLCipherBase : public CipherBase
{
  private:
    EVP_CIPHER_CTX* m_ctx_enc = nullptr;
    EVP_CIPHER_CTX* m_ctx_dec = nullptr;
    const uint8_t*  m_iv;
    const uint8_t*  m_key;
    uint32_t        m_key_len;
    alc_aes_mode_t  m_mode;

    void              handleErrors();
    const EVP_CIPHER* alcpModeKeyLenToCipher(alc_aes_mode_t mode,
                                             size_t         keylen);

  public:
    OpenSSLCipherBase(const alc_aes_mode_t mode, const uint8_t* iv);
    OpenSSLCipherBase(const alc_aes_mode_t mode,
                      const uint8_t*       iv,
                      const uint8_t*       key,
                      const uint32_t       key_len);
    ~OpenSSLCipherBase();
    bool init(const uint8_t* iv, const uint8_t* key, const uint32_t key_len);
    bool init(const uint8_t* key, const uint32_t key_len);
    bool encrypt(const uint8_t* plaintxt, size_t len, uint8_t* ciphertxt);
    bool decrypt(const uint8_t* ciphertxt, size_t len, uint8_t* plaintxt);
};
} // namespace alcp::testing
