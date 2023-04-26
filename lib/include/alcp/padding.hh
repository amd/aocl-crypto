/*
 * Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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

#pragma once

#include "alcp/base.hh"
#include "alcp/interface/Ipadder.hh"

#include <cstddef>
#include <vector>

namespace alcp {

enum class PaddingScheme
{
    eNone,       /* Generic padding will have byte/bit padding */
    ePkcs1_OAEP, /* Optimal Asymmetric Encryption Padding */
    x931,
    ePkcs1,
    ePss, /* Probabilistic Signature Scheme */
};

class MessageBlock
{
    using ByteVector = std::vector<std::byte>;

  public:
    /**
     * @brief    Returns number of bits in block
     * @return   Number of bits in block
     */
    Uint64 size() const;

    /**
     * @brief   Method to return reference to underlaying block
     * @return  Reference to underlaying message block as vector of bytes
     */
    ByteVector& get() const;

  private:
    /*
     * m_block contains the message in a byte accessible form,
     * the last byte contains the half-populated bits in its lower bits
     */
    ByteVector m_block;

    /*
     * if m_size_bits is not multiple of 8, then m_block contains at least one
     * byte which needs to be padded
     */
    Uint64 m_size_bits;
};

/**
 * @brief
 * NullPadder is a dummy class which doesnt' pad, useful when we have to have
 * a padder built into algorithms
 */
class NullPadder : public IPadder
{
  public:
    virtual Status pad(MessageBlock& msgBlk) { return StatusOk(); }
};

} // namespace alcp
