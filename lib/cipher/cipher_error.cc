/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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
 */

#include "alcp/cipher/cipher_error.hh"

namespace alcp::cipher::status {
// In future we can use just a template to represent all the below function
template<ErrorCode code>
inline Status
CipherErrorCode(String msg)
{
    auto e = CipherError(alcp::base::eInternal, code);
    return Status(e, msg);
}

// Functions for each error code
Status
InvaidValue(String msg)
{
    return CipherErrorCode<ErrorCode::eInvaidValue>(msg);
}
Status
NotPermitted(String msg)
{
    return CipherErrorCode<ErrorCode::eNotPermitted>(msg);
}
Status
AuthenticationFailure(String msg)
{
    return CipherErrorCode<ErrorCode::eAuthenticationFailure>(msg);
}
Status
InvalidCipher(String msg)
{
    return CipherErrorCode<ErrorCode::eInvalidCipher>(msg);
}
Status
InvalidMode(String msg)
{
    return CipherErrorCode<ErrorCode::eInvalidMode>(msg);
}
Status
HardwareFailed(String msg)
{
    return CipherErrorCode<ErrorCode::eHardwareFailed>(msg);
}
Status
DecryptFailed(String msg)
{
    return CipherErrorCode<ErrorCode::eDecryptFailed>(msg);
}
Status
EncryptFailed(String msg)
{
    return CipherErrorCode<ErrorCode::eEncryptFailed>(msg);
}
} // namespace alcp::cipher::status