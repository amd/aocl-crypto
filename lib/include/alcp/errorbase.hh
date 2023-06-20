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

#include "alcp/interface/Ierror.hh"
#include <string>
#include <unordered_map>

namespace alcp::base {

/**
 * @name ErrorBase
 * @detail
 * ErrorBase class is designed to work with different Error classes.
 * The errors are extendable to support dynamic module loading (plugin system).
 *
 */
class ALCP_API_EXPORT ErrorBase : public IError
{

  public:
    typedef Uint16 ModuleType;

    ErrorBase()
        : m_error{ 0 }
    {
    }

    ErrorBase(Uint16 module_error) { setModuleError(module_error); }

    ErrorBase(Uint64 code)
        : m_error{ code }
    {
    }

    /**
     * @brief     Overriden function to return code as 64-bit integer
     * @param     none
     * @return    A combined Uint64
     */
    virtual Uint64 code() const override { return m_error.val; }

    virtual const String message() const override final;

    static Uint16 codeToModuleId(Uint64 code)
    {
        uPackedT tmp = { code };
        return tmp.field.module_id;
    }

  protected:
    // Getter and Setter for generic error code
    void   setBaseError(Uint16 err) { m_error.field.base_error = err; }
    Uint16 getBaseError() const { return m_error.field.base_error; }

    // Getter and Setter for module specific error code
    void   setModuleError(Uint16 error) { m_error.field.module_error = error; }
    Uint16 getModuleError() const { return m_error.field.module_error; }

    /**
     * @brief   Getter function for module_id
     *
     * @return  an Uint16 compatible with module_id
     */
    Uint16 getModuleId() const { return m_error.field.module_id; }
    void   setModuleId(Uint16 mid) { m_error.field.module_id = mid; }

  protected:
    typedef union _uPacked
    {
        Uint64 val; // 8 Bytes

        struct _field
        {
            Uint64 base_error   : 16; // 2 Byte
            Uint64 module_error : 16; // 2 Byte
            Uint64 module_id    : 16; // 2 Byte
            Uint64 __reserved   : 16; // 2 Byte
        } field = {};
    } uPackedT;
    uPackedT m_error;

    //   static std::unordered_map<Uint16, IError> m_dispatcher_map;
};
} // namespace alcp::base
