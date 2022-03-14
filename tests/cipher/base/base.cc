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

#include "base.hh"
#include <iostream>

namespace alcp::testing {

/* Class File procedures */
File::File(std::string fileName)
{
    file.open(fileName, std::ios::in);
    if (file.is_open()) {
        fileExists = true;
    } else {
        fileExists = false;
    }
    return;
}

std::string
File::readWord()
{
    std::string buff;
    file >> buff;
    return buff;
}

std::string
File::readLine()
{
    std::string buff;
    std::getline(file, buff);
    return buff;
}

std::string
File::readLineCharByChar()
{
    std::string buff;
    while (!file.eof()) {
        char s = file.get();
        if (s != '\n')
            buff += s;
        else
            break;
    }
    return buff;
}

char*
File::readChar(int n)
{
    // TODO: Deallocation in the calling function.
    char* c_buff = new char[n];
    file.read(c_buff, n);
    return c_buff;
}

/* Class Data
/**
 * @brief Construct a new Data Set:: Data Set object
 *
 * @param filename
 */
DataSet::DataSet(std::string filename)
    : File(filename)
{
    line = readLine(); // Read header out
    return;
}

bool
DataSet::readPtIvKeyCt(int keybits)
{
    while (true) {
        if (readPtIvKeyCt() == false)
            return false;
        else if (key.size() * 8 == keybits)
            return true;
    }
}
bool
DataSet::readPtIvKeyCt()
{
#if 1
    line = readLine();
#else
    // Reference slower implementation
    line = readLineCharByChar();
    // std::cout << line << std::endl;
#endif
    if (line.empty() || line == "\n") {
        return false;
    }
    int pos1 = line.find(",");           // End of Plain Text (PT)
    int pos2 = line.find(",", pos1 + 1); // End of IV
    int pos3 = line.find(",", pos2 + 1); // End of Key
    if ((pos1 == -1) || (pos2 == -1) || (pos3 == -1)) {
        return false;
    }
    pt  = parseHexStrToBin(line.substr(0, pos1));
    iv  = parseHexStrToBin(line.substr(pos1 + 1, pos2 - pos1 - 1));
    key = parseHexStrToBin(line.substr(pos2 + 1, pos3 - pos2 - 1));
    ct  = parseHexStrToBin(line.substr(pos3 + 1));
    lineno++;
    return true;
}

uint8_t
DataSet::parseHexToNum(unsigned char c)
{
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= '0' && c <= '9')
        return c - '0';

    return 0;
}

std::vector<uint8_t>
DataSet::parseHexStrToBin(std::string in)
{
    std::vector<uint8_t> vector;
    int                  len = in.size();
    int                  ind = 0;

    for (int i = 0; i < len; i += 2) {
        uint8_t val =
            parseHexToNum(in.at(ind++)) << 4 | parseHexToNum(in.at(ind++));
        vector.push_back(val);
    }
    return vector;
}

int
DataSet::getLineNumber()
{
    return lineno;
}

std::vector<uint8_t>
DataSet::getPt()
{
    return pt;
}

std::vector<uint8_t>
DataSet::getIv()
{
    return iv;
}

std::vector<uint8_t>
DataSet::getKey()
{
    return key;
}

std::vector<uint8_t>
DataSet::getCt()
{
    return ct;
}

// Functions
unsigned char*
hexStringToBytes(std::string hexStr)
{
    const char* hexString = hexStr.c_str();
    int         length    = hexStr.size();
    if (length % 2 != 0) {
        return NULL;
    }
    // At this point we know size of hexString is even.

    // Need to dellocate after use
    unsigned char* outputBytes = new unsigned char[(length / 2) + 1];
    // unsigned char* outputBytes =
    //     (unsigned char*)malloc((sizeof(char) * length / 2) + 1);
    int outputBytesIndex = 0;
    for (int i = 0; i < length; i += 2) {
        unsigned char value     = 0;
        unsigned char outputval = 0;

        for (int j = 0; j < 2; j++) {

            // Master switchcase to compare char (most probably faster than
            // plain substract)
            switch (*(hexString + i + j)) {
                case '0':
                    value = 0x0;
                    break;
                case '1':
                    value = 0x1;
                    break;
                case '2':
                    value = 0x2;
                    break;
                case '3':
                    value = 0x3;
                    break;
                case '4':
                    value = 0x4;
                    break;
                case '5':
                    value = 0x5;
                    break;
                case '6':
                    value = 0x6;
                    break;
                case '7':
                    value = 0x7;
                    break;
                case '8':
                    value = 0x8;
                    break;
                case '9':
                    value = 0x9;
                    break;
                case 'a':
                    value = 0xa;
                    break;
                case 'b':
                    value = 0xb;
                    break;
                case 'c':
                    value = 0xc;
                    break;
                case 'd':
                    value = 0xd;
                    break;
                case 'e':
                    value = 0xe;
                    break;
                case 'f':
                    value = 0xf;
                    break;
            }

            // Most significant to least (otherway is faster.. meh)
            value = value << (4 * (2 - j - 1));
            // Acc the values into a single variable
            outputval = outputval | value;
        }
        // Set output with correct index
        *(outputBytes + outputBytesIndex) = outputval;
        // Can be done with eqn, we rnt runnin out of ram r we?
        outputBytesIndex++;
    }
    // Zero terminate for sanity.. AES won't care anyway
    outputBytes[outputBytesIndex] = 0x00;
    return outputBytes;
}

std::string
bytesToHexString(unsigned char* bytes, int length)
{
    char* outputHexString = new char[(sizeof(char) * ((length * 2) + 1))];
    for (int i = 0; i < length; i++) {
        char chararray[2];
        chararray[0] = (bytes[i] & 0xf0) >> 4; // Upper Half
        chararray[1] = bytes[i] & 0x0f;        // Lower Half
        for (int j = 0; j < 2; j++) {
            switch (chararray[j]) {
                case 0x0:
                    chararray[j] = '0';
                    break;
                case 0x1:
                    chararray[j] = '1';
                    break;
                case 0x2:
                    chararray[j] = '2';
                    break;
                case 0x3:
                    chararray[j] = '3';
                    break;
                case 0x4:
                    chararray[j] = '4';
                    break;
                case 0x5:
                    chararray[j] = '5';
                    break;
                case 0x6:
                    chararray[j] = '6';
                    break;
                case 0x7:
                    chararray[j] = '7';
                    break;
                case 0x8:
                    chararray[j] = '8';
                    break;
                case 0x9:
                    chararray[j] = '9';
                    break;
                case 0xa:
                    chararray[j] = 'a';
                    break;
                case 0xb:
                    chararray[j] = 'b';
                    break;
                case 0xc:
                    chararray[j] = 'c';
                    break;
                case 0xd:
                    chararray[j] = 'd';
                    break;
                case 0xe:
                    chararray[j] = 'e';
                    break;
                case 0xf:
                    chararray[j] = 'f';
                    break;
                default:
                    printf("%x %d\n", chararray[j], j);
            }
            outputHexString[i * 2 + j] = chararray[j];
        }
    }
    // Terminate output string to enable printing.
    outputHexString[length * 2] = 0x0;
    return std::string(outputHexString);
}
} // namespace alcp::testing
