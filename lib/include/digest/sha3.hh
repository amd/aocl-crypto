#include "digest.hh"
namespace alcp::digest {

  class Sha3 : public Digest
  {
  public:
    Sha3(const std::string& name)
      : m_name{ name }
    {}
    Sha3(const char* name)
      : Sha3(std::string(name))
    {}
    Sha3(const alc_digest_info_t& rDigestInfo);
    Sha3();
    ~Sha3();

  public:
    alc_error_t update(const uint8_t* pMsgBuf, Uint64 size);
    void finish();
    void reset();
    alc_error_t finalize(const uint8_t* pMsgBuf, Uint64 size);
    alc_error_t copyHash(uint8_t* pHashBuf, Uint64 size) const;
    alc_error_t setIv(const void* pIv, Uint64 size);
  private:
    void absorbChunk(Uint64* p_msg_buf_64);
    alc_error_t processChunk(const Uint8* pSrc, Uint64 len);
    inline void round(Uint64 round_const);
    void fFunction();

  private:
    std::string m_name;
    Uint64
      m_chunk_size_bits,
      m_capacity_bits,
      m_hash_size_bits,
      m_hash_size,
      m_chunk_size,
      m_chunk_size_u64;
    const Uint64
      m_state_size_bits = 1600,
      m_num_rounds = 24;
    Uint32
      m_idx;
    alc_sha2_mode_t
      m_mode = ALC_SHA3;
    bool
      m_finished;
    Uint8
      m_buffer[2* 2* (512 / 8)];
    // These sizes are to accomodate the max possible hash size, 512 bits.
    Uint64
      m_hash[2*  512 / 64],
      m_state[5][5],
      // flat representation of the state, used in absorbing the user message.
      // m_state[i][j] = state_flat[5*i + j], i.e. the final index of m_state
      // varies first to move in contiguous memory order.
      *m_state_flat = &m_state[0][0];
  };
}
