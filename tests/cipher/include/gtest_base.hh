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
#ifndef __GTEST_BASE_HH
#define __GTEST_BASE_HH 2

#include "alc_base.hh"
#include "base.hh"
#include "gtest_common.hh"
#include <vector>
#ifdef USE_IPP
#include "ipp_base.hh"
#endif
#ifdef USE_OSSL
#include "openssl_base.hh"
#endif

// Just a class to reduce duplication of lines
class TestingCore
{
  private:
    DataSet*        ds            = nullptr;
    CipherTesting*  cipherHandler = nullptr;
    AlcpCipherBase* acb           = nullptr;
#ifdef USE_IPP
    IPPCipherBase* icb = nullptr;
#endif
#ifdef USE_OSSL
    OpenSSLCipherBase* ocb = nullptr;
#endif
  public:
    TestingCore(lib_t lib, alc_aes_mode_t alcpMode)
    {
        cipherHandler = new CipherTesting();
        switch (lib) {
            case OPENSSL:
#ifndef USE_OSSL
                delete cipherHandler;
                throw "OpenSSL not avaiable!";
#else
                ocb = new OpenSSLCipherBase(alcpMode, NULL);
                cipherHandler->setcb(ocb);
#endif
                break;
            case IPP:
#ifndef USE_IPP
                delete cipherHandler;
                throw "IPP not avaiable!";
#else
                if (!useipp) {
                    delete cipherHandler;
                    throw "IPP disabled!";
                }
                icb = new IPPCipherBase(alcpMode, NULL);
                cipherHandler->setcb(icb);
#endif
                break;
            case ALCP:
                acb = new AlcpCipherBase(alcpMode, NULL);
                cipherHandler->setcb(acb);
                break;
        }
    }
    TestingCore(std::string modeStr, alc_aes_mode_t alcpMode)
    {
        std::transform(
            modeStr.begin(), modeStr.end(), modeStr.begin(), ::tolower);
        ds = new DataSet(std::string("dataset_") + modeStr
                         + std::string(".csv"));

        // Initialize cipher testing classes
        cipherHandler = new CipherTesting();
        acb           = new AlcpCipherBase(alcpMode, NULL);
        cipherHandler->setcb(acb);
#ifdef USE_IPP
        icb = new IPPCipherBase(alcpMode, NULL);
        if (useipp) {
            std::cout << "Using IPP" << std::endl;
            cipherHandler->setcb(icb);
        }
#else
        if (useipp) {
            printErrors("IPP is unavailable at the moment switching to ALCP!");
        }
#endif
#ifdef USE_OSSL
        ocb = new OpenSSLCipherBase(alcpMode, NULL);
        if (useossl) {
            std::cout << "Using OpenSSL" << std::endl;
            cipherHandler->setcb(ocb);
        }
#else
        if (useossl) {
            printErrors(
                "OpenSSL is unavailable at the moment switching to ALCP!");
        }
#endif
    }
    ~TestingCore()
    {
        if (ds != nullptr)
            delete ds;
        if (cipherHandler != nullptr)
            delete cipherHandler;
        if (acb != nullptr)
            delete acb;
#ifdef USE_IPP
        if (icb != nullptr)
            delete icb;
#endif
#ifdef USE_OSSL
        if (ocb != nullptr)
            delete ocb;
#endif
    }
    DataSet*       getDs() { return ds; }
    CipherTesting* getCipherHandler() { return cipherHandler; }
};

void
parseArgs(int argc, char** argv)
{
    std::string currentArg;
    if (argc > 1) {
        for (int i = 1; i < argc; i++) {
            currentArg = std::string(argv[i]);
            if ((currentArg == std::string("--help"))
                || (currentArg == std::string("-h"))) {
                std::cout << std::endl
                          << "Additional help for microtests" << std::endl;
                std::cout << "--verbose or -v per line status." << std::endl;
                std::cout << "--use-ipp or -i force IPP use in testing."
                          << std::endl;
                std::cout << "--use-ossl or -o force OpenSSL use in testing"
                          << std::endl;
            } else if ((currentArg == std::string("--verbose"))
                       || (currentArg == std::string("-v"))) {
                verbose = true;
            } else if ((currentArg == std::string("--use-ipp"))
                       || (currentArg == std::string("-i"))) {
                useipp = true;
            } else if ((currentArg == std::string("--use-ossl"))
                       || (currentArg == std::string("-o"))) {
                useossl = true;
            }
        }
    }
}

#endif