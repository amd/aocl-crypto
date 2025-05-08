/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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

#include <algorithm>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <vector>

#include "alcp/cipher.hh"
#include <alcp/alcp.h>

namespace filecrypt {
namespace utilities {
    /* Utilities */
    Uint8 parseHexToNum(const unsigned char c)
    {
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        if (c >= '0' && c <= '9')
            return c - '0';

        return 0;
    }
    std::vector<Uint8> parseHexStrToBin(const std::string in)
    {
        std::vector<Uint8> vector;
        int                len = in.size();
        int                ind = 0;

        for (int i = 0; i < len; i += 2) {
            Uint8 val =
                parseHexToNum(in.at(ind)) << 4 | parseHexToNum(in.at(ind + 1));
            vector.push_back(val);
            ind += 2;
        }
        return vector;
    }
    /* Depriciate padding once its implemented in all algorithms internally */
    class Padding
    {
      private:
      public:
        static std::vector<Uint8> padZeros(const std::vector<Uint8>& in)
        {
            Uint64             rem = 16 - (in.size() % 16);
            std::vector<Uint8> out = in;
            out.push_back(0x0f); // Pushing Excape, mark padding
            rem--;
            for (Uint64 i = 0; i < rem; i++) {
                out.push_back(0x00);
            }
            return out;
        }
        static std::vector<Uint8> unpadZeros(const std::vector<Uint8>& in)
        {
            std::vector<Uint8> escape = { 0x0f };
            auto               escape_index =
                std::find_end(
                    in.begin(), in.end(), escape.begin(), escape.end())
                - in.begin();
            return std::vector<Uint8>(in.begin(), in.begin() + escape_index);
        }
    };
} // namespace utilities

/* Classes */
/**
 * @class File
 *
 * @brief This class should handle binary files, should assist in getting
 *        blocks from the file or getting the entire data.
 *
 */
namespace framework {
    class File
    {
      private:
        std::unique_ptr<std::ifstream> iFile;
        std::unique_ptr<std::ofstream> oFile;
        bool                           write_mode = false;

      public:
        File(const std::string& filePath, bool input = true)
            : write_mode{ !input }
        {
            // Open File with read, binary access
            if (input)
                iFile =
                    std::make_unique<std::ifstream>(filePath, std::ios::binary);
            else
                oFile =
                    std::make_unique<std::ofstream>(filePath, std::ios::binary);
        }

        /**
         * @brief Check if the file status is ok
         * @return true if file is ready, otherwise false
         */
        bool isExists()
        {
            if (write_mode) {
                return oFile->good();
            } else {
                return iFile->good();
            }
        }

        /**
         * @brief End of File reached?
         * @return true if reached, false if not
         */
        bool isEOF() { return (iFile->peek() == EOF); }

        /**
         * @brief Reads entire bytes from a file
         * @return A vector of bytes (unsigned char)
         */
        std::vector<Uint8> readBytes()
        {
            if (write_mode) {
                return std::vector<Uint8>(0);
            }

            iFile->seekg(0, std::ios::end);
            Uint64             size = iFile->tellg();
            std::vector<Uint8> bytes;
            std::cout << "Vector Max Size:" << bytes.max_size()
                      << " Size Req:" << size << std::endl;
            bytes.resize(size);
            iFile->seekg(0, std::ios::beg);
            iFile->read((char*)&bytes[0], bytes.size());

            return bytes;
        }

        void writeBytes(const std::vector<Uint8>& in)
        {
            if (!write_mode) {
                return;
            }
            oFile->write(reinterpret_cast<const char*>(&in.at(0)), in.size());
            oFile->flush();
        }
        ~File()
        {
            if (!write_mode)
                iFile->close();
            if (write_mode)
                oFile->close();
        }
        // FIXME: Implement Partial File Read
    };

    /**
     * @class ArgParse
     *
     * @brief Parse the command line arguments into a map, the command line
     *        arguments can have arg,value pair or just arg
     *
     */
    class ArgParse
    {
      private:
        std::map<std::string, std::string> arg_map;

      public:
        /**
         * @brief Given argc and argv, it will parse the argumnets
         * @param argc Argument Count
         * @param argv Argument Values
         */
        ArgParse(int argc, char const* argv[])
        {
            if (argc <= 1) {
                return;
            }
            std::string s0 = argv[1];
            for (int i = 2; i < argc; i++) {
                std::string s1 = argv[i];
                if (s1.at(0) != '-') {
                    arg_map[s0] = s1;
                    s0          = "";
                    s1          = "";
                    i++;
                    if (i < argc) {
                        s0 = argv[i];
                    }
                } else {
                    arg_map[s0] = "";
                    s0          = s1;
                    s1          = "";
                }
            }
            if (s0 != "") {
                arg_map[s0] = "";
            }
        }

        /**
         * @brief Get Param Value as a string
         * @param param Param to get value of
         * @return Value of the given param
         */
        std::string getParamStr(std::string param)
        {
            if (arg_map.find(param) == arg_map.end()) {
                return ""; // Not set
            }
            return arg_map[param]; // Found so return what we have
        }

        /**
         * @brief Check if a prameter exists, with or without value
         * @param param Param to check if it exists
         * @return true if Pram exists otherwise false
         */
        bool exists(std::string param)
        {
            if (arg_map.find(param) == arg_map.end()) {
                return false;
            } else {
                return true;
            }
        }

        // FIXME: Implement Vectorization of Param Values
    };

    template<typename T>
    T* getPtr(std::vector<T>& vect)
    {
        if (vect.size() == 0) {
            return nullptr;
        } else {
            return &vect[0];
        }
    }

    template<typename T>
    const T* getPtr(const std::vector<T>& vect)
    {
        if (vect.size() == 0) {
            return nullptr;
        } else {
            return &vect[0];
        }
    }
} // namespace framework

namespace crypto {
    using alcp::cipher::CipherFactory;
    using alcp::cipher::iCipher;
    using framework::getPtr;
    class ICrypt
    {
      public:
        virtual std::vector<Uint8> encrypt(std::string&              mode,
                                           const std::vector<Uint8>& in,
                                           const std::vector<Uint8>& key,
                                           const std::vector<Uint8>& iv) = 0;

        virtual std::vector<Uint8> decrypt(std::string&              mode,
                                           const std::vector<Uint8>& in,
                                           const std::vector<Uint8>& key,
                                           const std::vector<Uint8>& iv) = 0;
        virtual void               setEncrypt()                          = 0;
        virtual ~ICrypt() = default;
    };

    class Crypt : public ICrypt
    {
      private:
        bool isEncrypt = false;

      public:
        void               setEncrypt() { isEncrypt = true; };
        std::vector<Uint8> encrypt(std::string&              mode,
                                   const std::vector<Uint8>& in,
                                   const std::vector<Uint8>& key,
                                   const std::vector<Uint8>& iv)
        {
            if (isEncrypt == false) {
                return std::vector<Uint8>(0);
            }

            std::vector<Uint8> out(in.size());
            alc_error_t        err;

            auto alcpCipher = new CipherFactory<iCipher>;
            auto aead       = alcpCipher->create(mode);

            if (aead == nullptr) {
                assert(aead != nullptr); // To be caught in debugging
                delete alcpCipher;
                return std::vector<Uint8>(0);
            }

            err =
                aead->init(getPtr(key), key.size() * 8, getPtr(iv), iv.size());
            if (err != ALC_ERROR_NONE) {
                printf("Error: Unable to Init \n");
                delete alcpCipher;
                return std::vector<Uint8>(0);
            }

            err = aead->encrypt(getPtr(in), getPtr(out), in.size());
            if (err != ALC_ERROR_NONE) {
                printf("Error: Unable to Encrypt \n");
                delete alcpCipher;
                return std::vector<Uint8>(0);
            }

            err = aead->finish(NULL);

            delete alcpCipher;
            return out;
        }
        std::vector<Uint8> decrypt(std::string&              mode,
                                   const std::vector<Uint8>& in,
                                   const std::vector<Uint8>& key,
                                   const std::vector<Uint8>& iv)
        {
            if (isEncrypt == true) {
                return std::vector<Uint8>(0);
            }
            std::vector<Uint8> out(in.size());

            alc_error_t err;
            auto        alcpCipher = new CipherFactory<iCipher>;
            auto        aead       = alcpCipher->create(mode);

            if (aead == nullptr) {
                assert(aead != nullptr); // To be caught in debugging
                delete alcpCipher;
                return std::vector<Uint8>(0);
            }

            err =
                aead->init(getPtr(key), key.size() * 8, getPtr(iv), iv.size());
            if (err != ALC_ERROR_NONE) {
                printf("Error: Unable to Init \n");
                delete alcpCipher;
                return std::vector<Uint8>(0);
            }

            err = aead->decrypt(getPtr(in), getPtr(out), in.size());
            if (err != ALC_ERROR_NONE) {
                printf("Error: Unable to Encrypt \n");
                delete alcpCipher;
                return std::vector<Uint8>(0);
            }

            err = aead->finish(NULL);

            delete alcpCipher;
            return out;
        }
        ~Crypt() { std::cout << "Crypt Destructor" << std::endl; }
    }; // namespace crypto

    class Encryptor
    {
      private:
        std::vector<Uint8>      cipherText = {};
        std::unique_ptr<ICrypt> crypt;

      protected:
        bool isEncrypt() const { return true; }

      public:
        Encryptor(std::unique_ptr<ICrypt> e)
        {
            crypt = std::move(e);
            crypt->setEncrypt();
        }

        std::vector<Uint8>& encrypt(std::string&              mode,
                                    const std::vector<Uint8>& in,
                                    const std::vector<Uint8>& key,
                                    const std::vector<Uint8>& iv)
        {
            std::vector<Uint8> padded_in = utilities::Padding::padZeros(in);
            cipherText = crypt->encrypt(mode, padded_in, key, iv);
            return cipherText;
        };

        ~Encryptor() = default;
    };

    class Decryptor
    {
      private:
        std::vector<Uint8>      plainText = {};
        std::unique_ptr<ICrypt> crypt;

      protected:
        bool isEncrypt() const { return false; }

      public:
        Decryptor(std::unique_ptr<ICrypt> e) { crypt = std::move(e); }

        std::vector<Uint8>& decrypt(std::string&              mode,
                                    const std::vector<Uint8>& in,
                                    const std::vector<Uint8>& key,
                                    const std::vector<Uint8>& iv)
        {
            std::vector<Uint8> padded_out = crypt->decrypt(mode, in, key, iv);
            plainText = utilities::Padding::unpadZeros(padded_out);
            return plainText;
        };

        ~Decryptor() = default;
    };
} // namespace crypto

void
printHelp()
{
    std::cout << "+-------------------------------------------+" << std::endl
              << "|  AOCL-Cryptography file-encryptor utility |" << std::endl
              << "+-------------------------------------------+" << std::endl
              << "| Command    |   Args                       |" << std::endl
              << "|-------------------------------------------|" << std::endl
              << "| --help/-h  |   None                       |" << std::endl
              << "| --iv       |   32 char hex encoded IV     |" << std::endl
              << "| --key      |   32-64 char hex encoded Key |" << std::endl
              << "| --alg      |   --alg aes-ctr-128          |" << std::endl
              << "| -i         |   Path to input file         |" << std::endl
              << "| -o         |   Path to output file        |" << std::endl
              << "| -e         |   Select Encrypt operation   |" << std::endl
              << "| -d         |   Select Decrypt operation   |" << std::endl
              << "+-------------------------------------------+" << std::endl;
}

} // namespace filecrypt

using namespace filecrypt;
int
main(int argc, char const* argv[])
{
    using utilities::parseHexStrToBin; // Hex string parser utility

    using framework::ArgParse; // Argument parser framework
    using framework::File;     // File manipulation framework

    using crypto::Crypt;     // Cryptographic Premitives
    using crypto::Decryptor; // Byte Decryptor
    using crypto::Encryptor; // Byte Encryptor

    std::string algorithm = "aes-cfb-128";
    /* code */
    ArgParse args = ArgParse(argc, argv);

    if (args.exists("--help") || args.exists("-h")) {
        printHelp();
        return 0;
    }

    if (!args.exists("--alg")) {
        std::cout << "Using default alg " << algorithm << std::endl;
    } else {
        algorithm = args.getParamStr("--alg");
    }

    std::vector<Uint8> key = parseHexStrToBin(args.getParamStr("--key"));
    std::vector<Uint8> iv  = parseHexStrToBin(args.getParamStr("--iv"));

    if (key.size() < 16 || iv.size() < 16) {
        std::cout << "Invalid argument!" << std::endl;
        printHelp();
        return -1;
    }

    bool isEncrypt = args.exists("-e");
    bool isDecrypt = args.exists("-d");

    if (isEncrypt == isDecrypt) {
        std::cout << "One of encrypt, decrypt must be specified, not both!"
                  << std::endl;
        printHelp();
        return -1;
    }

    File fi = File(args.getParamStr("-i"));
    File fo = File(args.getParamStr("-o"), false);

    if (!fi.isExists()) {
        std::cout << "Input file of the file do not exist!" << std::endl;
        return -1;
    }

    if (!fo.isExists()) {
        std::cout << "Cannot open output file for writing!" << std::endl;
        return -1;
    }

    std::vector<Uint8> data = fi.readBytes();

    if (isEncrypt) {
        Encryptor e(std::make_unique<Crypt>());
        data = e.encrypt(algorithm, data, key, iv);
    }
    if (isDecrypt) {
        Decryptor d(std::make_unique<Crypt>());
        data = d.decrypt(algorithm, data, key, iv);
    }

    fo.writeBytes(data);

    std::cout << "Success!" << std::endl;

    return 0;
}