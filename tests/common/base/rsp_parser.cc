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

CRspParser::CRspParser(String filename)
    : File(filename)
{
    m_input_rsp_file = filename;
    init(filename);
}

bool
CRspParser::init(String filename)
{
    std::cout<< "m_input_rsp_file: " << m_input_rsp_file << std::endl;
    int retVal = skipRSPHeader();
    if(m_fileEOF) {
        std::cout << "EOF Reached... No test cases found in " << m_input_rsp_file << std::endl;
        std::exit(EXIT_FAILURE);     
    }
    if(retVal) {
        std::cout << "Parsing header failed for : " << m_input_rsp_file << std::endl;
        std::exit(EXIT_FAILURE);
    }
    m_names.clear();
    m_data_vect.clear();
    return true;
}

/*
CRspParser::~CRspParser()
{
    m_TextFile.close();
}*/

// Function to get the index of deststr in srcstr
int 
CRspParser::isSubstring(String deststr, String srcstr) {
    // using find method to check if deststr is a substring of srcstr
    if (srcstr.find(deststr) != String::npos)
        return srcstr.find(deststr);
    return -1;
}

// Function to return a string containing up to |len| characters 
// from |str| with leading and trailing whitespace removed.
String 
CRspParser::stripWhiteSpaceChar(const char *str, size_t len) {
    // Remove Leading Space
    while (len > 0 && isspace(*str))
    {
        str++;
        len--;
    }
    // Remove Trailing Space
    while (len > 0 && isspace(str[len-1]))
    {
        len--;
    }
    return String(str, len);
}
/* findDelimiter returns a pointer to the first '=' or ':' in a line
// or nullptr if there is none.
const char*
CRspParser::findDelimiter(const char *str) {
  while (*str) {
    if (*str == ':' || *str == '=') {
      return str;
    }
    str++;
  }
  return nullptr;
}*/

// Function to read Key and Value from a Parameter
// Value is always the content next to the delmiter ("=")
std::pair<std::string, std::string>  
CRspParser::readParamKeyValue(String str)
{
    String key, value;
    int pos = isSubstring("=", str);
    
    if (pos == -1)
    {
        key = str;
        value = nullptr;
    }
    else
    {
        size_t const len = str.size()-pos+1;
        key = str.substr(0,pos);
        value = str.substr(pos+1, len);
    }

    return {adjustKeyNames(key),value};
}

// Function to remove spaces within a String
String
CRspParser::removeSpaces(String str)
{
    str.erase(remove(str.begin(), str.end(), ' '), str.end());
    str = stripWhiteSpaceChar(str.data(), str.size());
    return str;
}

// Vectorize a String based on comma seperated values
// Used to read Params from a TC (line in .txt)
 std::vector<String>
 CRspParser::vectorizeParams(String myStr) {
    const char delim = ',';
    std::vector<String> myVec;

    myVec.clear();  // NALINI - FIX-ME: Is this reqd? Scope of vector?
    myVec.push_back("");
            
    for(size_t i=0; i<myStr.size(); i++)
    {
        int n=myVec.size();
        //if comma is found push a new empty string to the vector
        if(myStr[i]==delim)
            myVec.push_back("");
        //if no comma, keep pushing the char to the last string of the vector
        else 
            myVec[n-1].push_back(myStr[i]); 
    }
    // Remove any empty elements in the vector
    myVec.erase( remove( myVec.begin(), myVec.end(), "" ), myVec.end() );
    return myVec;
 }

// Vectorize each Parameter based on '='
// Used to read key-value pair from a Param
 int
 CRspParser::vectorize(std::vector<String> params_vec) {
    m_data_vect.clear();
            
    for(size_t i=0; i<params_vec.size(); i++) {
        // NALINI - FIX-ME: Ignore if only 1 parameter present. Eg: seed
        if (params_vec.size() < 2){
            continue;
        }
        m_data_vect.push_back(data_elm_t("", ""));
        m_data_vect.at(i) = readParamKeyValue(params_vec[i]);
    }
    // Remove any empty elements in the vector
    //m_data_vect.erase( remove( m_data_vect.begin(), m_data_vect.end(), "" ), m_data_vect.end() );
    //for(auto& tuple: m_data_vect) 
        //std::cout << std::get<0>(tuple) << " " << std::get<1>(tuple) << std::endl;
    return 0;
 }

// Thus function skips the header from the Input RSP File  
int 
CRspParser::skipRSPHeader() 
{
    if (!CheckFileExists()) {
        std::cout << "File doesnt exist: " << m_input_rsp_file << std::endl;
        return -1;
    }
  
    //  To skip the header
    bool search_lines = true;
    while (search_lines) {
        m_lineBuf = readMyLine();
        if (m_fileEOF) break;

        // Any way the line is read so increment
        m_lineno++;
        if(m_lineBuf[0] == '#' || m_lineBuf[0] == '[')
            continue;
        else if ( m_lineBuf == "\r"){
            search_lines = false;
            break;
        }
    }
    //std::cout <<m_lineno<<":"<<m_lineBuf << std::endl;
    std::cout << "Header Parsed...." << std::endl;
    return 0;
}

// Thus function gets all Paramaters of single TC from the 
// RSP File into a comma seperated String
String
CRspParser::FetchTCfromRSP() 
{
    String myTestCase {};
    static size_t TC_Count {0};
    
    bool newTC = false;
    while (!newTC) {
        m_lineBuf = readMyLine();
        if (m_fileEOF) {
            TC_Count++;
            break; // EOF reached
        }
        m_lineno++; // Line is read
        //std::cout <<m_lineno<<":"<<m_lineBuf << std::endl;
    
        if(m_lineBuf[0] == '#' || m_lineBuf[0] == '[') continue;
        else if (isSubstring("Seed", m_lineBuf) != -1) { 
            //std::cout << "Seed string.." << std::endl;
            continue;
        }
        else if(m_lineBuf == "\r") {
            // New Section or New Test case is encountered.
            if(myTestCase.empty()) continue;
            newTC = true;
            TC_Count++;
        }
        else {
            // Get an input test case
            String myStr = removeSpaces(m_lineBuf);
            myTestCase = myTestCase.append(myStr) + ",";
        }
    }
    //std::cout << TC_Count << ":myTestCase:" << myTestCase << std::endl;
    return myTestCase;
}

// Parse Next Test Case from "m_output_text_file" and store in m_data_vect
bool
CRspParser::readNextTC() {
    // All Parameters in each TC to be stored as a vector
    std::vector<String> params_vec;
    static bool keysParsed = false;

    // Get one TC in a one-lined String
    m_lineBuf = FetchTCfromRSP();
    if (m_fileEOF && m_lineBuf.empty()) return false;
    //std::cout << m_lineno <<":readNextTC:"<<m_lineBuf << std::endl;

    // Got a valid Line
    m_paramPerTC = count(m_lineBuf.begin(), m_lineBuf.end(), ',');
    // Get all Parameters in each TC stored as a vector
    params_vec = vectorizeParams(m_lineBuf);
    
    // Get all Key-Value pairs in each TC stored as a vector
    int retVal = vectorize(params_vec);
    if (retVal != 0) {
        printf("Failed to vectorize Key-Value pairs at Line: %d\n", m_lineno);
        return false;
    }
    // Vectorize m_names (Store Keys in a vector to align original imple)
    if (m_data_vect.size() > 0 && keysParsed == false ) {
        for (size_t i = 0; i < m_data_vect.size(); i++) {
            m_names.push_back("");
            m_names.at(i) = std::get<0>(m_data_vect[i]);
            //std::cout << m_names[i] << std::endl;
        }
    keysParsed = true;
    }
    return true;
}

// Be very careful with this, as if its not a hexstring, it will return
// zeros.
std::vector<Uint8>
CRspParser::getVect(const String cName)
{
    String value = getStr(cName);
    //std::cout << value << std::endl;
    return parseHexStrToBin(value);
}

// Returns Value based on predefined "Key" from m_data_vect
String
CRspParser::getStr(const String cName)
{
    // Linear Search
    for (Uint64 i = 0; i < m_data_vect.size(); i++) {
        String id, value;
        std::tie(id, value) = m_data_vect.at(i);
        if (id == cName) {
            return value;
        }
    }
    return String();
}

// Map the Key names with that of Algorithm Specific Parameter names
String
CRspParser::adjustKeyNames(String cName) {
    String myKey = "";
    if (cName == "Msg")
        myKey = "MESSAGE";
    else if (cName == "Output" || cName == "MD")
        myKey = "DIGEST";
    else if (cName == "Outputlen")
        myKey = "DIGESTLEN";
    else if (cName == "COUNT")
        myKey = "TestCount";
    else myKey = cName;
    return myKey;
}

int
CRspParser::getLineNumber()
{
    return m_lineno;
}

} // namespace alcp::testing