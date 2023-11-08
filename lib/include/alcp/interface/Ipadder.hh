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

#pragma once

#include "alcp/base/status.hh"
#include "alcp/defs.hh"

namespace alcp {

// forward declaration
class MessageBlock;

/**
 * @name        IPadder - The padder Interface
 *
 * @details
 * Algorithms hold a reference to this, the wrap the bytes in a MessageBlock and
 * send for padding
 */
class IPadder
{
  public:
    ALCP_DEFS_DEFAULT_CTOR_AND_EMPTY_VIRTUAL_DTOR(IPadder);

  public:
    /**
     *
     * @brief
     * Each Padder inherently knows how to pad
     *
     * @details
     * The details of padding scheme is internal to the
     *
     * @param   msgBlk  Reference to the Message Block which needs to be padded
     *
     * @return  Status of the padding operation
     */
    virtual Status pad(MessageBlock& msgBlk) = 0;

    /**
     *
     * @brief
     * Allows padding with specified bits
     *
     * @details
     * Each block is associated with bit length, the last byte has the
     * bits in its lowest place if bit-length,
     *
     * @param   valueBits       kind of treated as bit-string embedded in Uin64
     * @param   msgBlk  Reference to the Message Block which needs to be padded
     *
     * @return  Stautus of padding operation
     */
    virtual Status padBits(MessageBlock& msgBlk, Uint64 valueBits);

    /**
     * @brief
     * Allow padding with Byte, useful when aligning to byte length
     *
     * @details
     * Assumption bit-length is multiple of 8,
     *
     * @param   msgBlk  Reference to the Message Block which needs to be padded
     * @param   valueBits       kind of treated as bit-string embedded in Uin64
     *
     * @return Status of padding operation
     */
    virtual Status padBytes(MessageBlock& msgBlk, Uint64 valueByte);

    /**
     * @brief
     * Pads remaining bytes with 0
     *
     * @details
     * if the bit-lenght is not a multple of 8, the last byte contains bits in
     * the LSB Such bits are shifted left before appending zeroes
     *
     * @param   msgBlk  Reference to the Message Block which needs to be padded
     * @param   count   number of zeros to be added (in bytes)
     *
     * @return Status of padding operation
     */
    virtual Status padZero(MessageBlock& msgBlk, Uint64 count);
};
} // namespace alcp
