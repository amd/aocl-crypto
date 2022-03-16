#include <alcp/alcp.h>
#include <iostream>
#include <ippcp.h>
#include <stdio.h>
#include <string.h>

class IPPCipherBase
{
  private:
    alc_aes_mode_t m_mode;
    IppsAESSpec*   m_pAES = 0;
    const uint8_t* m_iv;
    const uint8_t* m_key;
    uint32_t       m_key_len;
    int            m_ctxSize = 0;
    bool alcpModeToFuncCall(const uint8_t* in, uint8_t* out, int len, bool enc);

  public:
    /**
     * @brief Construct a new Alcp Base object - Manual initilization needed,
     * run alcpInit
     *
     * @param mode
     * @param iv
     */
    IPPCipherBase(const alc_aes_mode_t mode, const uint8_t* iv);
    /**
     * @brief Construct a new Alcp Base object - Initlized and ready to go
     *
     * @param mode
     * @param iv
     * @param key
     * @param key_len
     */
    IPPCipherBase(const alc_aes_mode_t mode,
                  const uint8_t*       iv,
                  const uint8_t*       key,
                  const uint32_t       key_len);
    /**
     * @brief         Initialization/Reinitialization function, created handle
     *
     * @param iv      Intilization vector or start of counter (CTR mode)
     * @param key     Binary(RAW) Key 128/192/256 bits
     * @param key_len Length of the Key
     * @return true -  if no failure
     * @return false - if there is some failure
     */
    ~IPPCipherBase();
    bool alcpInit(const uint8_t* iv,
                  const uint8_t* key,
                  const uint32_t key_len);
    bool alcpInit(const uint8_t* key, const uint32_t key_len);
    bool encrypt(const uint8_t* plaintxt, const int len, uint8_t* ciphertxt);
    bool decrypt(const uint8_t* ciphertxt, const int len, uint8_t* plaintxt);
};