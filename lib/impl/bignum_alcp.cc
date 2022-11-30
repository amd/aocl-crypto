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

#include "alcp/utils/bignum.hh"

namespace alcp {

class BigNum::Impl
{
  public:
    Impl();
    ~Impl();

  public:
    BigNum add(const BigNum& rhs);

#if 0
    BigNum sub(const BigNum& rhs);
    BigNum mul(const BigNum& rhs);
    BigNum div(const BigNum& rhs);
    BigNum mod(const BigNum& rhs);

    /* Cant compare BigNum at the moment */
    inline bool neq(const BigNum& rhs) { return true; }

    /* Cant compare BigNum at the moment */
    inline bool eq(const BigNum& rhs) { return false; }
#endif
};

BigNum
BigNum::Impl::add(const BigNum& rhs)
{
	BigNum result;
	if(avx512_supported())
		bn_add_512(result.c_ptr(), this->c_ptr(), rhs.c_ptr());

	bn_add_512(this->c_ptr(), this->c_ptr(), rhs.c_ptr());
	return result;
}


} // namespace alcp
