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

#pragma once

#include "alcp/base/assert.hh"
#include "alcp/types.hh"

#include <memory>

namespace alcp {

template<typename T>
class ArrayView
{
    typedef T&                                   referenceT;
    typedef const T&                             constReferenceT;
    typedef T*                                   pointerT;
    typedef const T*                             constPointerT;
    typedef T                                    valueT;
    typedef std::reverse_iterator<pointerT>      reverseIteratorT;
    typedef std::reverse_iterator<constPointerT> constReverseIteratorT;

  public:
    explicit ArrayView(void* ptr, size_t size)
        : ArrayView<T>{ static_cast<pointerT>(ptr), size }
    {
    }

    explicit ArrayView(pointerT ptr, size_t size)
        : m_ptr{ ptr }
        , m_size{ size }
    {
    }

    pointerT data() { return m_ptr[0]; }

    constPointerT data() const { return m_ptr[0]; }

    /**********
     * Array Access members
     ***********/
    referenceT operator[](std::size_t i) { return at(i); }

    constReferenceT operator[](std::size_t i) const { return at(i); }

    referenceT at(std::size_t i)
    {
        if (i >= m_num_elements) {
            ALCP_ASSERT(i >= m_num_elements, "Out of range access on array");
        }

        return static_cast<pointerT>(m_ptr.get())[i];
    }

    constReferenceT at(std::size_t i) const
    {
        if (i >= m_num_elements) {
            ALCP_ASSERT(i >= m_num_elements, "Out of range access on array");
        }

        return static_cast<pointerT>(m_ptr.get())[i];
    }

    /**********
     * Iterator helpers
     ***********/
    pointerT begin() { return &m_ptr[0]; }

    constPointerT begin() const { return &m_ptr[0]; }

    pointerT end() { return &m_ptr[m_num_elements]; }

    constPointerT end() const { return m_ptr + m_num_elements; }

    reverseIteratorT rbegin() { return reverse_pointerT(end()); }

    constReverseIteratorT rbegin() const { return constReversePointerT(end()); }

    reverseIteratorT rend() { return reverse_pointerT(begin()); }

    constReverseIteratorT rend() const { return constReversePointerT(begin()); }

    constPointerT cbegin() const { return &m_ptr[0]; }

    constPointerT cend() const { return &m_ptr[m_num_elements]; }

    constReverseIteratorT crbegin() const
    {
        return constReversePointerT(end());
    }

    constReverseIteratorT crend() const
    {
        return constReversePointerT(begin());
    }

  private:
    struct _Deleter
    { /* Disable deleting as we dont own the memory */
        void operator()(pointerT ptr){};
    };
    using uniquePointerT = std::unique_ptr<valueT, _Deleter>;

    uniquePointerT m_ptr;
    std::size_t    m_size;
    std::size_t    m_num_elements;
};

} // namespace alcp
