#include "base.hh"
#include <iostream>

namespace alcp::bench {

/* Class File procedures */
File::File(const std::string fileName)
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
File::readChar(const int n)
{
    // TODO: Deallocation in the calling function.
    char* c_buff = new char[n];
    file.read(c_buff, n);
    return c_buff;
}

/**
 * @brief Construct a new Data Set:: Data Set object
 *
 * @param filename
 */
DataSet::DataSet(const std::string filename)
    : File(filename)
{
    line = readLine(); // Read header out
    return;
}


bool
DataSet::readMsgDigest()
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
    int pos1 = line.find(",");           // End of Msg
    if ((pos1 == -1)) {
        printf ("Error in parsing csv\n");
        return false;
    }
    Message  = parseHexStrToBin(line.substr(0, pos1));
    Digest = parseHexStrToBin(line.substr(pos1 + 1));
    lineno++;
    return true;
}

uint8_t
DataSet::parseHexToNum(const unsigned char c)
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
DataSet::parseHexStrToBin(const std::string in)
{
    std::vector<uint8_t> vec(in.begin(), in.end());
    return vec;
}

std::string
DataSet::parseBytesToHexStr(const uint8_t* bytes, const int length)
{
    std::stringstream ss;
    for (int i = 0; i < length; i++) {
        int charRep;
        charRep = bytes[i];
        // Convert int to hex
        ss << std::hex << charRep;
    }
    return ss.str();
}

int
DataSet::getLineNumber()
{
    return lineno;
}

std::vector<uint8_t>
DataSet::getMessage()
{
    return Message;
}

std::vector<uint8_t>
DataSet::getDigest()
{
    return Digest;
}

} // namespace alcp::bench