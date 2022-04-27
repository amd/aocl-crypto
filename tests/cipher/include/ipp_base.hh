/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */
#pragma once
#include "base.hh"
#include <alcp/alcp.h>
#include <iostream>
#include <ippcp.h>
#include <stdio.h>
#include <string.h>

#ifndef __IPP_BASE_HH
#define __IPP_BASE_HH 2
namespace alcp::testing {
class IPPCipherBase : public CipherBase
{
  private:
    alc_aes_mode_t m_mode;
    IppsAESSpec*   m_ctx = 0;
    IppsAES_GCMState* pState = NULL;
    const uint8_t* m_iv;
    const uint8_t* m_key;
    uint32_t       m_key_len;
    int            m_ctxSize = 0;
    bool           alcpModeToFuncCall(const uint8_t* in,
                                      uint8_t*       out,
                                      size_t         len,
                                      bool           enc);

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
    bool init(const uint8_t* iv, const uint8_t* key, const uint32_t key_len);
    bool init(const uint8_t* key, const uint32_t key_len);
    bool encrypt(const uint8_t* plaintxt, size_t len, uint8_t* ciphertxt);
    bool encrypt(alcp_data_ex_t data);
    bool decrypt(const uint8_t* ciphertxt, size_t len, uint8_t* plaintxt);
    bool decrypt(alcp_data_ex_t data);
    void reset();
};
} // namespace alcp::testing
#endif