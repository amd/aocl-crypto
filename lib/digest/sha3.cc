#include <cstdint>
#include <cmath>
#include "digest.hh"
#include "digest/sha3.hh"

#include <algorithm>
#include <climits>
#include <functional>
#include <string>
#include <iostream>

#ifdef USE_AOCL_CPUID
#include "alci/cpu_features.h"
#endif

#include "digest/sha2.hh"
#include "digest/sha_avx2.hh"

#include "utils/bits.hh"
#include "utils/copy.hh"
#include "utils/endian.hh"

namespace utils = alcp::utils;

namespace alcp::digest {  

  static constexpr Uint64
  ///  
  c_round_consts [24] =
    {
      0x0000000000000001,
      0x0000000000008082,
      0x800000000000808A,
      0x8000000080008000,
      0x000000000000808B,
      0x0000000080000001,
      0x8000000080008081,
      0x8000000000008009,
      0x000000000000008A,
      0x0000000000000088,
      0x0000000080008009,
      0x000000008000000A,
      0x000000008000808B,
      0x800000000000008B,
      0x8000000000008089,
      0x8000000000008003,
      0x8000000000008002,
      0x8000000000000080,
      0x000000000000800A,
      0x800000008000000A,
      0x8000000080008081,
      0x8000000000008080,
      0x0000000080000001,
      0x8000000080008008
    },
  ///
    c_rot_consts [5][5] =
      {
        0, 36,  3, 41, 18,
        1, 44, 10, 45,  2,
        62,  6, 43, 15, 61,
        28, 55, 25, 21, 56,
        27, 20, 39,  8, 14
      };
  ///
  Sha3::Sha3(){}
  ///
  Sha3::Sha3(const alc_digest_info_t& rDigestInfo)
  {
    m_hash_size_bits = rDigestInfo.dt_len;
    switch(m_hash_size_bits) {
    case 224:
      m_chunk_size_bits = 1152;
      break;
    case 256:
      m_chunk_size_bits = 1088;
      break;
    case 384:
      m_chunk_size_bits = 832;
      break;
    case 512:
      m_chunk_size_bits = 576;
      break;
    default:
      ;
    }
    m_capacity_bits = m_state_size_bits - m_chunk_size_bits;
    m_chunk_size_u64 = m_chunk_size_bits / 64;
    m_chunk_size = m_chunk_size_bits / 8;
    m_hash_size = m_hash_size_bits / 8;

    for (Uint64 i=0; i<25; ++i){
      m_state_flat[i] = 0;
    }
  }

  Sha3::~Sha3(){
  }

  ///
  void Sha3::absorbChunk(Uint64* pMsgBuffer64){
    for (Uint64 i = 0; i < m_chunk_size_u64; ++i){
      m_state_flat[i] ^= pMsgBuffer64[i];
    }
  }

  inline void Sha3::round(Uint64 roundConst){
    ///
    //theta
    Uint64 temp[5];
    for (int x = 0; x < 5; ++x){
      temp[x] = m_state[x][0] xor m_state[x][1] xor m_state[x][2] xor m_state[x][3] xor m_state[x][4];
    }  
    for (int x = 0; x < 5; ++x){
      for (int y = 0; y < 5; ++y){
        //possible: rot wrong way?
        m_state[x][y] ^= (temp[(x-1)%5] xor alcp::digest::RotateRight(temp[(x+1)%5], 1));
      }
    }

    ///
    Uint64 temp2[5][5];
    //pho and pi
    for (int x = 0; x < 5; ++x){
      for (int y = 0; y < 5; ++y){
        temp2[y][(2*x + 3*y)%5] = alcp::digest::RotateRight(m_state[x][y], c_rot_consts[x][y]);     
      }
    }

    ///
    //xi
    for (int x = 0; x < 5; ++x){
      for (int y = 0; y < 5; ++y){
        m_state[x][y] = temp2[x][y] xor (~temp2[(x+1)%5][y] & temp2[(x+2)%5][y]);
      }
    }

    ///
    //iota
    m_state[0][0] ^= roundConst;
  }

  ///
  void
  Sha3::fFunction(){
    for (Uint64 i=0 ; i<m_num_rounds; ++i){
      round(c_round_consts[i]);
    }
  }
  
  alc_error_t
  Sha3::setIv(const void* pIv, Uint64 size){
    utils::CopyBytes(m_state_flat, pIv, size);
    return ALC_ERROR_NONE;
  }

  void
  Sha3::reset(){
    m_finished = false;
    m_idx      = 0;
  }

  alc_error_t
  Sha3::copyHash(Uint8* pHash, Uint64 size) const
  {
    alc_error_t err = ALC_ERROR_NONE;
    // hash must be copied from m_state, because for sha3, iterations do not operate on the hash directly.
    // Hash is first m_hash_size_bits, which is the first 
    utils::CopyBlockWith<Uint64>(
           pHash, m_state_flat, m_hash_size, utils::ToBigEndian<Uint64>);
    return err;
  }



  // possible: read  error is process, update or finalise
  alc_error_t
  Sha3::processChunk(const Uint8* pSrc, Uint64 len)
  {

    /* we need len to be multiple of m_chunk_size */
    assert((len & m_chunk_sizeMask) == 0);
    
    Uint64  msg_size       = len;
    Uint64* p_msg_buffer64 = (Uint64*)pSrc;

    while (msg_size) {
      // xor message chunk into m_state.
      absorbChunk(p_msg_buffer64);
      fFunction();

      p_msg_buffer64 += m_chunk_size_u64;
      msg_size -= m_chunk_size;
    }

    return ALC_ERROR_NONE;
  }

  alc_error_t
  Sha3::update(const Uint8* pSrc, Uint64 inputSize)
  {

    alc_error_t err = ALC_ERROR_NONE;

    if (m_finished) {
      Error::setGeneric(err, ALC_ERROR_INVALID_ARG);
      return err;
    }
    if (inputSize == 0) {
      return err;
    }

    Uint64 to_process = std::min((inputSize + m_idx), m_chunk_size);
    if (to_process < m_chunk_size) {
      /* copy them to internal buffer and return */
      utils::CopyBytes(&m_buffer[m_idx], pSrc, inputSize);
      m_idx += inputSize;
      return err;
    }

    Uint64 idx = m_idx;

    if (idx) {
      /*
       * Last call to update(), had some unprocessed bytes which is part
       * of internal buffer, we process first block by copying from pSrc the
       * remaining bytes of a chunk.
       */
      to_process = std::min(inputSize, m_chunk_size - idx);
      utils::CopyBytes(&m_buffer[idx], pSrc, to_process);

      pSrc += to_process;
      inputSize -= to_process;
      idx += to_process;

      if (idx == m_chunk_size) {
        err = processChunk(m_buffer, m_chunk_size);
        idx = 0;
      }
    }

    /* Calculate leftover bytes that can be processed as multiple chunks */
    Uint64 num_chunks = inputSize / m_chunk_size;
    if (num_chunks) {
      Uint64 size = num_chunks * m_chunk_size;
      err = processChunk(pSrc, size);
      pSrc += size;
      inputSize -= size;
    }

    /*
     * We still have some leftover bytes, copy them to internal buffer
     */
    if (inputSize) {
      utils::CopyBytes(&m_buffer[idx], pSrc, inputSize);
      idx += inputSize;
    }

    m_idx = idx;

    return err;
  }

  alc_error_t
  Sha3::finalize(const Uint8* pBuf, Uint64 size)
  {
    alc_error_t err = ALC_ERROR_NONE;

    if (m_finished)
      return err;

    if (pBuf && size)
      err = update(pBuf, size);

    // sha3 padding
    if (m_idx == m_chunk_size - 1){
      // if one byte is available, fill it with 01100001
      m_buffer[m_idx++] = 0x61;
    }
    else {
      // if more than one byte is available, fill first with 01100000,
      // then fill all but the first and last (which may be none) with 00000000,
      // then fill the last with 00000001
      m_buffer[m_idx++] = 0x60;
      for (; m_idx < m_chunk_size - 1; ++m_idx){
        m_buffer[m_idx] = 0x00;
      }      
      m_buffer[m_idx++] = 0x01;
    }

    if (Error::isError(err)) {
      return err;
    }
    
    err = processChunk(m_buffer, m_chunk_size);
    m_idx = 0;
    m_finished = true;

    return err;
  }

  void  
  Sha3::finish(){
  }  
}
