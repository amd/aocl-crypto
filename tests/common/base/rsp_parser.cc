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

#include "rsp_parser.hh"

namespace alcp::testing {

CRspParser::CRspParser(const String& filename)
   : File(filename)
{
    m_input_rsp_file = filename;
    m_file_exists = CheckFileExists();
    if (!m_file_exists) {
        //std::cout << "File doesnt exist: " <<  m_input_rsp_file << std::endl;
        utils::printErrors("File doesnt exist: " + m_input_rsp_file);
        return;
    }
    init();
}

bool
CRspParser::init()
{
    bool retVal = skipRSPHeader();
    if(!retVal) {
        //std::cout << "Parsing header failed for : " << m_input_rsp_file << std::endl;
        utils::printErrors("Parsing header failed for : " + m_input_rsp_file);
        return false;
    }
    m_names.clear();
    m_data_map.clear();
    return true;
}

/* Function to get the index of deststr in srcstr   */
int
CRspParser::isSubstring(StringView deststr, StringView srcstr) {
    size_t index = srcstr.find(deststr);
    if ( index != String::npos)
        return index;
    return -1;
}

/*  Function to remove white space characters within a String
    Whitespace chars: ‘ ‘, ‘\t’, ‘\n’, ‘\r’, ‘\v’, ‘\f’
*/
void
CRspParser::removeSpaces(String& str)
{
    str.erase(remove_if(str.begin(), str.end(), ::isspace), str.end());
}

/* Vectorize a TC based on "," into params_vec 
  Store each Parameter based on '=' in UMap
  Used to read key-value pair from a Param
*/
void
CRspParser::StoreTCinUMap(StringView myStr)
{
    m_data_map.clear();

    String key {}, value {}, myParam {};
    int pos {};
    
    // Vectorize a TC into params_vec based on
    // comma seperated values
    for (size_t i =0;i < m_paramPerTC; i++) {    
        pos = isSubstring(",", myStr);
        myParam = myStr.substr(0, pos);
        myStr = myStr.begin()+pos+1;

        // Store each param from params_vec into m_data_map 
        pos = isSubstring("=", myParam);
        if (pos == -1) {
            key = myParam;
            //value = nullptr;
            value = myParam;    // GCM Seg Fault when "FAIL" in TC
        }
        else {
            size_t len = myParam.size()-pos+1;
            key = myParam.substr(0,pos);
            value = myParam.substr(pos+1, len);
        }
        
        String myKey = adjustKeyNames(key);
        m_data_map[myKey] = value;
    }
}

/* Thus function skips the header from the Input RSP File  */
bool 
CRspParser::skipRSPHeader() 
{
    bool search_lines {true};
    while (search_lines) {
        if(!getline(m_file, m_lineBuf)) {
            m_fileEOF = true;
            utils::printErrors(".. EOF Reached....");
            break;
        }

        // Any way the line is read, so increment
        m_lineno++;
        if(m_lineBuf[0] == '#' || m_lineBuf[0] == '[')
            continue;
        else if ( m_lineBuf == "\r") {
            search_lines = false;
            break;
        }
    }
    //std::cout << "Header Parsed...." << std::endl;
    utils::printErrors("Header Parsed....");
    return true;
}

/* This function gets all Paramaters of single TC from the 
   RSP File into a comma seperated String
*/
String
CRspParser::FetchTCfromRSP() 
{
    String myTestCase {};
    static size_t TC_Count {0};
    
    bool newTC {false};
    while (!newTC) {
        if(!getline(m_file, m_lineBuf)) {
            m_fileEOF = true;
            TC_Count++;
            utils::printErrors("... EOF Reached....");
            break;
        }

        m_lineno++; // Line is read
        if(m_lineBuf[0] == '#' || m_lineBuf[0] == '[') continue;
        else if(m_lineBuf == "\r") {
            // New Section or New Test case is encountered.
            if(myTestCase.empty()) continue;
            newTC = true;
            TC_Count++;
        }
        else {
            // Get an input test case
            removeSpaces(m_lineBuf);
            myTestCase = myTestCase.append(m_lineBuf) + ",";
        }
    }
    // Print for test/debug purpose
    std::cout << TC_Count << ":myTestCase:" << myTestCase << std::endl;
    return myTestCase;
}

/* Parse Next Test Case and store in m_data_map    */
bool
CRspParser::readNextTC()
{
    static bool keysParsed {false};
    String myTC {};

    // Get one TC in a one-lined String
    myTC = FetchTCfromRSP();
    if (m_fileEOF && myTC.empty()) return false;

    m_paramPerTC = count(myTC.begin(), myTC.end(), ',');
    
    // Store Key-Value pairs per TC in an unordered_map
    StoreTCinUMap(myTC);

    // Vectorize m_names (Store Keys in a vector to align "csv" imple)
    if (m_data_map.size() > 0 && keysParsed == false ) {
        m_names.reserve(m_data_map.size());
        for(auto i : m_data_map) {
            m_names.push_back(i.first);
        } 
    keysParsed = true;
    }
    return true;
}

/* Returns "Uint8 Value" based on the "Key" from m_data_map */
std::vector<Uint8>
CRspParser::getVect(StringView cName)
{
    String key {}, value {};
    key = cName;
    if (m_data_map.find(key)!= m_data_map.end())
        value =  m_data_map[key];

    // To create a byte for single digit numerals
    if (value.size() % 2 ==0) 
        return parseHexStrToBin(value);
    else
        return parseHexStrToBin("0" + value);
}

/* Returns "Uint64 Value" in bytes based on the "Length" key from m_data_map */
Uint64
CRspParser::getLenBytes(StringView cName)
{
    String key {}, value {};
    key = cName;
    if (m_data_map.find(key)!= m_data_map.end())
        value =  m_data_map[key];

    return (utils::parseStrToUint64(value))/8;
}
    
/*  Map the Key names with that of Algorithm Specific 
    Parameter names
 */
String
CRspParser::adjustKeyNames(String cName)
{
    String myKey {};
    
    // Unordered Map to store key names from different modes
    param_map_t keyMap = {{"Msg", "MESSAGE"}, 
    {"Len", "MESSAGELEN"}, {"MD", "DIGEST"}, 
    {"Output", "DIGEST"}, {"Outputlen", "DIGESTLEN"}, 
    {"PT", "PLAINTEXT"}, {"CT", "CIPHERTEXT"}, 
    {"Key", "KEY"}, {"IV", "INITVECT"}, {"Nonce", "INITVECT"}, 
    {"Tag", "TAG"}, {"AAD", "AD"}, {"TKey", "TWEAK_KEY"}, 
    {"CKey", "CTR_KEY"}};
    
    if (keyMap.find(cName)!= keyMap.end())
        myKey =  keyMap[cName];
    else myKey = cName;

    return myKey;
}

Uint
CRspParser::getLineNumber()
{
    return m_lineno;
}

} // namespace alcp::testing