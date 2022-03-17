#pragma once
#include <fstream>
#include <sstream>
#include <vector>

namespace alcp::bench {
class File
{
  private:
    std::fstream file;
    bool         fileExists;

  public:
    // Opens File as ASCII Text File
    File(std::string fileName);
    // Read file word by word excludes newlines and spaces
    std::string readWord();
    // Read file line by line
    std::string readLine();
    // Reads a line by reading char by char
    std::string readLineCharByChar();
    // Read file n char
    char* readChar(int n);
    // Rewind file to initial position
    void rewind();
};

class DataSet : private File
{
  private:
    std::string          line = "";
    std::vector<uint8_t> Message, Digest;
    // First line is skipped, linenum starts from 1
    int lineno = 1;

  public:
    // Treats file as CSV, skips first line
    DataSet(const std::string filename);
    // Read without condition
    bool readMsgDigest();
    // Convert a hex char to number;
    uint8_t parseHexToNum(const unsigned char c);
    // Parse hexString to binary
    std::vector<uint8_t> parseHexStrToBin(const std::string in);
    std::string parseBytesToHexStr(const uint8_t* bytes, const int length);
    // To print which line in dataset failed
    int getLineNumber();
    /* fetch Message / Digest */
    std::vector<uint8_t> getMessage();
    std::vector<uint8_t> getDigest();
};
} // namespace alcp::testing
