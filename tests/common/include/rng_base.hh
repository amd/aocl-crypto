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
 *
 */

#pragma once
#include <alcp/alcp.h>
#include <random>
#include <vector>

namespace alcp::testing {
class RngBase
{
  private:
    alc_rng_handle_t m_handle{ nullptr };
    std::mt19937     mt_rand_;
    Uint64           m_seed_;

  public:
    RngBase();
    ~RngBase();

    /**
     * @brief Near to Pure Random Generator.
     *
     * @param l Size of buffer
     * @return Vector of bytes with random numbers
     */
    std::vector<Uint8> genRandomBytes(std::size_t l);

    /**
     * @brief Purely psedudo random number generator.
     *
     * Based on seed value provided or internally generated using genRandomBytes
     * will use mt19937 to create deterministic bytes from uniform distribution
     *
     * @param buffer Buffer, with preallocated memory to store the random
     * numbers
     */
    void genRandomMt19937(std::vector<Uint8>& buffer);

    /**
     * @brief Override the seed to generate stream using the seed.
     *
     * Same seed will mean it will never generate any other random number
     *
     * @param seed 64 bit seed input
     */
    void setSeedMt19937(Uint64 seed);

    /**
     * @brief Get the interal seed for storage purpose
     *
     * In case to investigate you can get the seed out.
     *
     * @return 64 bit seed output
     */
    Uint64 getSeedMt19937();
};
} // namespace alcp::testing