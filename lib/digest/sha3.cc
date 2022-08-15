#include <cstdint>
#include <cmath>
#include "digest.hh"
#include "digest/sha3.hh"

#include <algorithm>
#include <iostream>
#include <climits>
#include <functional>
#include <string>

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
  round_consts [24] =
    {
      0x0000000000000001, 0x000000008000808B, 0x0000000000008082, 0x800000000000008B, 0x800000000000808A,
      0x8000000000008089, 0x8000000080008000, 0x8000000000008003, 0x000000000000808B, 0x8000000000008002,
      0x0000000080000001, 0x8000000000000080, 0x8000000080008081, 0x000000000000800A, 0x8000000000008009,
      0x800000008000000A, 0x000000000000008A, 0x8000000080008081, 0x0000000000000088, 0x8000000000008080,
      0x0000000080008009, 0x0000000080000001, 0x000000008000000A, 0x8000000080008008
    },
    rot_consts [5][5] =
      {
        0, 36,  3, 41, 18,
        1, 44, 10, 45,  2,
        62,  6, 43, 15, 61,
        28, 55, 25, 21, 56,
        27, 20, 39,  8, 14
      };



  Sha3::Sha3(){}
  Sha3::Sha3(const alc_digest_info_t& rDigestInfo)
  {
    hash_size_bits = rDigestInfo.dt_len;
    switch(hash_size_bits) {
    case 224:
      chunk_size_bits = 1152;
      break;
    case 256:
      chunk_size_bits = 1088;
      break;
    case 384:
      chunk_size_bits = 832;
      break;
    case 512:
      chunk_size_bits = 576;
      break;
    default:
      ;
      // error here
    }
    capacity_bits = state_size_bits - chunk_size_bits;
    chunk_size_u64 = chunk_size_bits / 64;
    chunk_size = chunk_size_bits / 8;
    hash_size = hash_size_bits / 8;
    m_buffer = new Uint8[2* (hash_size_bits / 8)];
    m_hash = new Uint64[hash_size_bits / 64];
  }

  Sha3::~Sha3(){
    delete[] m_buffer;
    delete[] m_hash;
  }

  void Sha3::absorb_chunk(Uint64 *state_flat, Uint64* p_msg_buffer64){
    std::cout << *state_flat << " state init\n";
    std::cout << *p_msg_buffer64 << " buff\n";
    for (Uint64 i = 0; i < chunk_size_u64; ++i){
      state_flat[i] ^= p_msg_buffer64[i];
    }
    std::cout << *state_flat << " state final\n" ;
  }

  inline void Sha3::round(Uint64 round_const){
    // state is Uint64[5][5]

    //theta
    Uint64 temp1[5];
    for (int x = 0; x < 5; ++x){
      temp1[x] = state[x][0] xor state[x][1] xor state[x][2] xor state[x][3] xor state[x][4];
    }  
    for (int x = 0; x < 5; ++x){
      for (int y = 0; y < 5; ++y){
        state[x][y] = state[x][y] xor temp1[(x-1)%5] xor alcp::digest::RotateRight(temp1[(x+1)%5], 1);
      }
    }
    
    //pho and pi
    Uint64 temp2[5][5], temp3[5][5]; 
    for (int x = 0; x < 5; ++x){
      for (int y = 0; y < 5; ++y){
        temp2[x][y] = alcp::digest::RotateRight(state[x][y], rot_consts[x][y]);
      }
    }
    for (int x = 0; x < 5; ++x){
      for (int y = 0; y < 5; ++y){
        temp3[y][(2*x + 3*y)%5] = temp2[x][y];     
      }
    }

    //xi
    for (int x = 0; x < 5; ++x){
      for (int y = 0; y < 5; ++y){
        state[x][y] = temp3[x][y] xor (~temp3[(x+1)%5][y]^temp3[(x+2)%5][y]);
      }
    }
    
    //iota
    state[0][0] += round_const;
  }

  void Sha3::f_function(){
    const int n_rounds = 24;
    for (int i=0 ; i<n_rounds; ++i){
      round(round_consts[i]);
    }
  }
  
  alc_error_t
  Sha3::setIv(const void* pIv, Uint64 size)
  {
    utils::CopyBytes(m_hash, pIv, size);

    return ALC_ERROR_NONE;
  }

  void
  Sha3::reset()
  {
    m_msg_len  = 0;
    m_finished = false;
    m_idx      = 0;
  }


  alc_error_t
  Sha3::copyHash(Uint8* pHash, Uint64 size) const
  {
    alc_error_t err = ALC_ERROR_NONE;

    // hash must be copied from state, because for sha3, iterations do not operate on the hash directly.
    // Hash is first hash_size_bits, which is the first 

    utils::CopyBlockWith<Uint64>(
           pHash, state, hash_size, utils::ToBigEndian<Uint64>);
    
    return err;
  }


  alc_error_t
  Sha3::processChunk(const Uint8* pSrc, Uint64 len)
  {

    // static bool avx2_available = isAvx2Available();
    /* we need len to be multiple of chunk_size */
    assert((len & chunk_sizeMask) == 0);

    // if (avx2_available) {
    //   return avx2::ShaUpdate512(m_hash, pSrc, len, cRoundConstants);
    // }

    Uint64  msg_size       = len;
    Uint64* p_msg_buffer64 = (Uint64*)pSrc;

    // flat representation of the state, used in absorbing the user message.
    // state[i][j] = state_flat[5*i + j], i.e. the final index of state varies first, to move in memory order.
    Uint64 *state_flat = &state[0][0];
    absorb_chunk(state_flat, p_msg_buffer64);

    while (msg_size) {
      // xor message chunk into state.
      f_function();

      p_msg_buffer64 += chunk_size_u64;
      msg_size -= chunk_size;
    }

    return ALC_ERROR_NONE;
  }

  alc_error_t
  Sha3::update(const Uint8* pSrc, Uint64 input_size)
  {

    alc_error_t err = ALC_ERROR_NONE;

    if (m_finished) {
      Error::setGeneric(err, ALC_ERROR_INVALID_ARG);
      return err;
    }

    /*shani
     * Valid request, last computed has itself is good,
     * default is m_iv
     */
    if (input_size == 0) {
      return err;
    }
    m_msg_len += input_size;
    Uint64 to_process = std::min((input_size + m_idx), chunk_size);
    if (to_process < chunk_size) {
      /* copy them to internal buffer and return */
      utils::CopyBytes(&m_buffer[m_idx], pSrc, input_size);
      m_idx += input_size;
      return err;
    }

    Uint64 idx = m_idx;

    if (idx) {
      /*
       * Last call to update(), had some unprocessed bytes which is part
       * of internal buffer, we process first block by copying from pSrc the
       * remaining bytes of a chunk.
       */
      to_process = std::min(input_size, chunk_size - idx);
      utils::CopyBytes(&m_buffer[idx], pSrc, to_process);

      pSrc += to_process;
      input_size -= to_process;
      idx += to_process;

      if (idx == chunk_size) {
        err = processChunk(m_buffer, chunk_size);
        idx = 0;
      }
    }

    /* Calculate leftover bytes that can be processed as multiple chunks */
    Uint64 num_chunks = input_size / chunk_size;
    if (num_chunks) {
      Uint64 size = num_chunks * chunk_size;
      err = processChunk(pSrc, size);
      pSrc += size;
      input_size -= size;
    }

    /*
     * We still have some leftover bytes, copy them to internal buffer
     */
    if (input_size) {
      utils::CopyBytes(&m_buffer[idx], pSrc, input_size);
      idx += input_size;
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

    if (Error::isError(err)) {
      return err;
    }

    /*
     * We may have some left over data for which the hash to be computed
     * padding the rest of it to ensure correct computation
     * Padding =  "01" ||  "1" ||  n * "0" || 1, where n is the smallest positive
     * int that results in len(last_message || padding) % chunk_size_bits = 0.
     * padding and all commented out stuff below TODO
     */

    /*
     * When the bytes left in the current chunk are less than 8,
     * current chunk can NOT accomodate the message length.
     * The curent chunk is processed and the message length is
     * placed in a new chunk and will be processed.
     */
    m_buffer[m_idx++] = 0x80;

    //    Uint64 buf_len = m_idx < (chunk_size - 16) ? chunk_size : sizeof(m_buffer);
    //    Uint64 bytes_left = buf_len - m_idx - utils::BytesInDWord<Uint64>;
    //    Uint64 bytes_left = buf_len - m_idx - 16;

    //    utils::PadBlock<Uint8>(&m_buffer[m_idx], 0x0, bytes_left);


    // #ifdef __SIZEOF_INT128__
    //     /* Store total length in the last 128-bit (16-bytes) */
    //     __uint128_t  len_in_bits = m_msg_len * 8;
    //     __uint128_t* msg_len_ptr = reinterpret_cast<__uint128_t*>(
    //                                                               &m_buffer[buf_len] - sizeof(__uint128_t));
    //     msg_len_ptr[0] = utils::ToBigEndian(len_in_bits);
    // #else
    //     Uint64 len_in_bits_high;
    //     Uint64 len_in_bits;

    //     if (m_msg_len > ULLONG_MAX / 8) { // overflow happens
    //       // extract the left most 3bits
    //       len_in_bits_high = m_msg_len >> 61;
    //       len_in_bits = m_msg_len << 3;

    //     } else {
    //       len_in_bits_high = 0;
    //       len_in_bits = m_msg_len * 8;
    //     }
    //     Uint64* msg_len_ptr =
    //       reinterpret_cast<Uint64*>(&m_buffer[buf_len] - (sizeof(Uint64) * 2));
    //     msg_len_ptr[0] = utils::ToBigEndian(len_in_bits_high);
    //     msg_len_ptr[1] = utils::ToBigEndian(len_in_bits);
    // #endif
    //    err = processChunk(m_buffer, buf_len);

    m_idx = 0;

    m_finished = true;


    

    return err;
  }
  /*
    void Sha3::pad(Uint8 *chunk, int n_zeros, Uint64 chunk_size){
    // assuming byte aligned source for now
    // not yet correct
    Uint64 num_bytes = (n_zeros + 4) / 8;
    chunk[chunk_size - num_bytes] = 1 + 3*std::pow(2,n_zeros-1)
    }
  */
  void  
  Sha3::finish()
  {
    // delete pImpl();
    // pImpl() = nullptr;
  }

  
}
