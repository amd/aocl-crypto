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
 *
 */
#if !defined _BIGNUMBER_H_
#define _BIGNUMBER_H_

#include <iostream>
#include <ippcp.h>
#include <iterator>
#include <vector>
using namespace std;

class BigNumber
{
  public:
    BigNumber();
    BigNumber(Ipp32u value = 0);
    BigNumber(Ipp32s value);
    BigNumber(const IppsBigNumState* pBN);
    BigNumber(const Ipp32u* pData,
              int           length = 1,
              IppsBigNumSGN sgn    = IppsBigNumPOS);
    BigNumber(const BigNumber& bn);
    BigNumber(const char* s);
    virtual ~BigNumber();

    static void Test(void);

    // get
    IppStatus GetOctetString(unsigned char* pMsg, int len);
    void      GetSize(int* pLength);
    void      Get(Ipp32u* pData, int* pLength, IppsBigNumSGN* pSgn);

    // set value
    void Set(const Ipp32u* pData,
             int           length = 1,
             IppsBigNumSGN sgn    = IppsBigNumPOS);
    // conversion to IppsBigNumState
    friend IppsBigNumState* BN(const BigNumber& bn) { return bn.m_pBN; }
                            operator IppsBigNumState*() const { return m_pBN; }

    // some useful constatns
    static const BigNumber& Zero();
    static const BigNumber& One();
    static const BigNumber& Two();

    // arithmetic operators probably need
    BigNumber&       operator=(const BigNumber& bn);
    BigNumber&       operator+=(const BigNumber& bn);
    BigNumber&       operator-=(const BigNumber& bn);
    BigNumber&       operator*=(Ipp32u n);
    BigNumber&       operator*=(const BigNumber& bn);
    BigNumber&       operator/=(const BigNumber& bn);
    BigNumber&       operator%=(const BigNumber& bn);
    friend BigNumber operator+(const BigNumber& a, const BigNumber& b);
    friend BigNumber operator-(const BigNumber& a, const BigNumber& b);
    friend BigNumber operator*(const BigNumber& a, const BigNumber& b);
    friend BigNumber operator*(const BigNumber& a, Ipp32u);
    friend BigNumber operator%(const BigNumber& a, const BigNumber& b);
    friend BigNumber operator/(const BigNumber& a, const BigNumber& b);

    // modulo arithmetic
    BigNumber Modulo(const BigNumber& a) const;
    BigNumber ModAdd(const BigNumber& a, const BigNumber& b) const;
    BigNumber ModSub(const BigNumber& a, const BigNumber& b) const;
    BigNumber ModMul(const BigNumber& a, const BigNumber& b) const;
    BigNumber InverseAdd(const BigNumber& a) const;
    BigNumber InverseMul(const BigNumber& a) const;

    // comparisons
    friend bool operator<(const BigNumber& a, const BigNumber& b);
    friend bool operator>(const BigNumber& a, const BigNumber& b);
    friend bool operator==(const BigNumber& a, const BigNumber& b);
    friend bool operator!=(const BigNumber& a, const BigNumber& b);
    friend bool operator<=(const BigNumber& a, const BigNumber& b)
    {
        return !(a > b);
    }
    friend bool operator>=(const BigNumber& a, const BigNumber& b)
    {
        return !(a < b);
    }

    // easy tests
    bool IsOdd() const;
    bool IsEven() const { return !IsOdd(); }

    // size of BigNumber
    int        MSB() const;
    int        LSB() const;
    int        BitSize() const { return MSB() + 1; }
    int        DwordSize() const { return (BitSize() + 31) >> 5; }
    friend int Bit(const vector<Ipp32u>& v, int n);

    // conversion and output
    void num2hex(string& s) const;         // convert to hex string
    void num2vec(vector<Ipp32u>& v) const; // convert to 32-bit word vector
    friend ostream& operator<<(ostream& os, const BigNumber& a);

  protected:
    bool             create(const Ipp32u* pData,
                            int           length,
                            IppsBigNumSGN sgn = IppsBigNumPOS);
    int              compare(const BigNumber&) const;
    IppsBigNumState* m_pBN;
};

// convert bit size into 32-bit words
#define BITSIZE_WORD(n) ((((n) + 31) >> 5))

#endif // _BIGNUMBER_H_
