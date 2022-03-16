#include "ipp_base.hh"

IPPCipherBase::IPPCipherBase(const alc_aes_mode_t mode, const uint8_t* iv)
    : m_mode{ mode }
    , m_iv{ iv }
{}

IPPCipherBase::IPPCipherBase(const alc_aes_mode_t mode,
                             const uint8_t*       iv,
                             const uint8_t*       key,
                             const uint32_t       key_len)
    : m_mode{ mode }
    , m_iv{ iv }
    , m_key{ key }
    , m_key_len{ key_len }
{

    IppStatus status = ippStsNoErr;
    status           = ippsAESGetSize(&m_ctxSize);
    m_pAES           = (IppsAESSpec*)(new Ipp8u[m_ctxSize]);
    status           = ippsAESInit(key, key_len, m_pAES, m_ctxSize);
}

IPPCipherBase::~IPPCipherBase()
{
    if (m_pAES != nullptr) {
        delete[](Ipp8u*) m_pAES;
    }
}
bool
IPPCipherBase::alcpInit(const uint8_t* iv,
                        const uint8_t* key,
                        const uint32_t key_len)
{
    m_iv = iv;
    return alcpInit(key, key_len);
}

bool
IPPCipherBase::alcpInit(const uint8_t* key, const uint32_t key_len)
{
    m_key            = key;
    m_key_len        = key_len;
    IppStatus status = ippStsNoErr;
    status           = ippsAESGetSize(&m_ctxSize);
    if (m_pAES != nullptr) {
        delete[](Ipp8u*) m_pAES;
        ;
    }
    m_pAES = (IppsAESSpec*)(new Ipp8u[m_ctxSize]);
    status = ippsAESInit(key, key_len, m_pAES, m_ctxSize);
    return true;
}

bool
IPPCipherBase::alcpModeToFuncCall(const uint8_t* in,
                                  uint8_t*       out,
                                  int            len,
                                  bool           enc)
{
    IppStatus status = ippStsNoErr;
    uint8_t   iv[16];
    memcpy(iv, m_iv, 16);
    switch (m_mode) {
        case ALC_AES_MODE_CBC:
            if (enc) {
                status = ippsAESEncryptCBC(in, out, len, m_pAES, iv);
            } else {
                status = ippsAESDecryptCBC(in, out, len, m_pAES, iv);
            }
            break;
        case ALC_AES_MODE_CFB:
            if (enc) {
                status = ippsAESEncryptCFB(in, out, len, 16, m_pAES, iv);
            } else {
                status = ippsAESDecryptCFB(in, out, len, 16, m_pAES, iv);
            }
            break;
        case ALC_AES_MODE_OFB:
            if (enc) {
                status = ippsAESEncryptOFB(in, out, len, 16, m_pAES, iv);
            } else {
                status = ippsAESDecryptOFB(in, out, len, 16, m_pAES, iv);
            }
            break;
        case ALC_AES_MODE_CTR:
            if (enc) {
                status = ippsAESEncryptCTR(in, out, len, m_pAES, iv, 128);
            } else {
                status = ippsAESDecryptCTR(in, out, len, m_pAES, iv, 128);
            }
            break;
        default:
            return false;
    }
    return true;
}

bool
IPPCipherBase::encrypt(const uint8_t* plaintxt,
                       const int      len,
                       uint8_t*       ciphertxt)
{
    alcpModeToFuncCall(plaintxt, ciphertxt, len, true);
    return true;
}

bool
IPPCipherBase::decrypt(const uint8_t* ciphertxt,
                       const int      len,
                       uint8_t*       plaintxt)
{
    alcpModeToFuncCall(ciphertxt, plaintxt, len, false);
    return true;
}

#ifdef MAIN
std::string
bytesToHexString(unsigned char* bytes, int length)
{
    char* outputHexString = new char[(sizeof(char) * ((length * 2) + 1))];
    for (int i = 0; i < length; i++) {
        char chararray[2];
        chararray[0] = (bytes[i] & 0xf0) >> 4;
        chararray[1] = bytes[i] & 0x0f;
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
    outputHexString[length * 2] = 0x0;
    std::string ret             = std::string(outputHexString);
    free(outputHexString);
    return ret;
}

int
main()
{
    uint8_t iv[16];
    uint8_t key[16];

    size_t  len = 32;
    uint8_t pt[len];
    uint8_t ct[len];

    memset(iv, 0, 16);
    memset(key, 1, 16);
    memset(pt, 0, len);

    IPPCipherBase acb = IPPCipherBase(ALC_AES_MODE_OFB, iv, key, 16);
    for (int i = 0; i < 100000; i++)
        acb.encrypt(pt, len, ct);
    std::cout << bytesToHexString(ct, len) << std::endl;
}
#endif