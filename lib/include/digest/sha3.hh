#include "digest.hh"
namespace alcp::digest {

  class Sha3 : public Digest
  {
  public:
    Sha3(int hash_size_bits);
    Sha3(const std::string& name)
      : m_name{ name }
      , m_msg_len{ 0 }
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
    void absorb_chunk(Uint64 *state_flat, Uint64* p_msg_buf_64);
    alc_error_t processChunk(const Uint8* pSrc, Uint64 len);
    inline void round(Uint64 round_const);
    void f_function();
  private:
    std::string     m_name;
    Uint64 m_msg_len;
    /* Any unprocessed bytes from last call to update() */
    Uint8  *m_buffer;
    Uint64 *m_hash;
    Uint64 state[5][5];
    /* index to m_buffer of previously unprocessed bytes */
    Uint32 m_idx;
    bool   m_finished;
    alc_sha2_mode_t m_mode;
    Uint64 chunk_size_bits,
      capacity_bits,
      hash_size_bits,
      hash_size,
      chunk_size,
      chunk_size_u64;
    const Uint64 state_size_bits = 1600, num_rounds = 24;
    
  };
}
