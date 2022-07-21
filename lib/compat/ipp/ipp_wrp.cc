#include <iostream>
#include <ippcp.h>
#include <stdint.h>
#include <alcp/alcp.h>
#include <string.h>
#include "context.hh"


IppStatus ippsAES_XTSGetSize(int * pSize){
    *pSize = sizeof(ipp_wrp_ctx);
    return ippStsNoErr;
}

IppStatus ippsAES_GCMGetSize(int * pSize){
    *pSize = sizeof(ipp_wrp_ctx);
    return ippStsNoErr;
}



