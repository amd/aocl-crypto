/*
 * Copyright (C) 2022-2024, Advanced Micro Devices. All rights reserved.
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

#include "alcp/base/assert.hh"
#include "alcp/base/status.hh"

#include <optional>

namespace alcp::base {

template<typename T>
class StatusOr
{
  public:
    // using value_type = T;
    // using type       = T;

  public:
    inline StatusOr();
    inline StatusOr(Status& sts);

    inline StatusOr(const T& val);
    inline StatusOr(T&& val);

    ALCP_DEFS_DEFAULT_COPY_AND_ASSIGNMENT(StatusOr);

    /**
     * @brief status() will return the underlying status
     *
     * {
     *      StatusOr<Aes256Context> sts = Aes::Build("aes-256-cbc")
     *
     *      if (!sts.ok()) {
     *          return sts.status();
     *      }
     *
     *      auto val = *sts;
     *
     * }
     *
     * @return const Status&
     */
    inline const Status& status() const { return m_status; }
    inline bool          ok() const { return m_status.ok(); }

    T value() const {}

    /**
     * @brief  Returns reference to underlaying object
     * @other  Requires this->ok() to be true, otherwise behaviour is undefined
     *
     * @details Use this->ok() to make sure there is an object 'T'.
     *          When in doubt use the StatusOr<T>::value() API to ensure
     *          appropriate safe behaviour
     */
    T&        operator*() &;
    T&&       operator*() &&;
    const T&  operator*() const&;
    const T&& operator*() const&&;

    /**
     * @brief Returns pointer to current value
     *
     * @details Use this->ok() to make sure there was no error and object
     *          of type 'T' is valid
     */
    const T* operator->() const;
    T*       operator->();

  private:
    std::optional<T> m_value;
    Status           m_status;

  private:
    inline bool assertNotOk() const
    {
        ALCP_ASSERT(!m_status.ok(), m_status.message());
        return m_status.ok();
    }
};

template<typename T>
inline StatusOr<T>::StatusOr()
    : m_status{ StatusOk() }
{
}

template<typename T>
inline StatusOr<T>::StatusOr(Status& sts)
    : m_status{ sts }
{
    ALCP_ASSERT(!m_status.ok(), "Assigned status not ok!!");
}

template<typename T>
inline StatusOr<T>::StatusOr(const T& value)
    : m_value{ value }
{
}

template<typename T>
inline StatusOr<T>::StatusOr(T&& value)
    : m_value{ std::move(value) }
{
}

} // namespace alcp::base
