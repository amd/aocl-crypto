#ifndef _INCLUDE_AES_AESNI_MACRO_HH_
#define _INCLUDE_AES_AESNI_MACRO_HH_ 2

#define AES_BLOCK_SIZE(x) ((x) / 8)


#define SINGLE_KEY_LOAD 1//Non -macro based implementation

//Load AES keys for 10 rounds in xmm register
#define ALCP_AES_LOAD_KEYS_10_ROUND_XMM(X) \
	__m128i key_128_0, key_128_1, key_128_2,\
	        key_128_3, key_128_4, key_128_5,\
			key_128_6, key_128_7, key_128_8,\
			key_128_9, key_128_10;\
	\
	key_128_0  = _mm_loadu_si128(pkey128);\
	key_128_1  = _mm_loadu_si128(pkey128+1);\
	key_128_2  = _mm_loadu_si128(pkey128+2);\
	key_128_3  = _mm_loadu_si128(pkey128+3);\
	key_128_4  = _mm_loadu_si128(pkey128+4);\
	key_128_5  = _mm_loadu_si128(pkey128+5);\
	key_128_6  = _mm_loadu_si128(pkey128+6);\
	key_128_7  = _mm_loadu_si128(pkey128+7);\
	key_128_8  = _mm_loadu_si128(pkey128+8);\
	key_128_9  = _mm_loadu_si128(pkey128+9);\
	key_128_10 = _mm_loadu_si128(pkey128+10);

//Load AES extra 2x128bit keys for 12 rounds in xmm register
#define ALCP_AES_LOAD_KEYS_12_ROUND_XMM_EXTRA2(X) \
	__m128i key_128_11, key_128_12;\
	key_128_11 = _mm_loadu_si128(pkey128+11);\
	key_128_12 = _mm_loadu_si128(pkey128+12);

//Load AES extra 2x128bit keys for 14 rounds in xmm register
#define ALCP_AES_LOAD_KEYS_14_ROUND_XMM_EXTRA2(X) \
	__m128i key_128_13, key_128_14;\
	key_128_13 = _mm_loadu_si128(pkey128+13);\
	key_128_14 = _mm_loadu_si128(pkey128+14);

/****************** 128x2 = 256 bit *************************/

/* 128 bit aes encrypt and decrypt MACROS */

/* 10 rounds*/
// enc
#define ALCP_AESENC_128BIT_10ROUND(A, KEY) \
	A =_mm_aesenc_si128(A, KEY##_1);\
	A =_mm_aesenc_si128(A, KEY##_2);\
	A =_mm_aesenc_si128(A, KEY##_3);\
	A =_mm_aesenc_si128(A, KEY##_4);\
	A =_mm_aesenc_si128(A, KEY##_5);\
	A =_mm_aesenc_si128(A, KEY##_6);\
	A =_mm_aesenc_si128(A, KEY##_7);\
	A =_mm_aesenc_si128(A, KEY##_8);\
	A =_mm_aesenc_si128(A, KEY##_9);

// dec
#define ALCP_AESDEC_128BIT_10ROUND(A, KEY) \
	A =_mm_aesdec_si128(A, KEY##_1);\
	A =_mm_aesdec_si128(A, KEY##_2);\
	A =_mm_aesdec_si128(A, KEY##_3);\
	A =_mm_aesdec_si128(A, KEY##_4);\
	A =_mm_aesdec_si128(A, KEY##_5);\
	A =_mm_aesdec_si128(A, KEY##_6);\
	A =_mm_aesdec_si128(A, KEY##_7);\
	A =_mm_aesdec_si128(A, KEY##_8);\
	A =_mm_aesdec_si128(A, KEY##_9);

/* 12 rounds */
// enc
#define ALCP_AESENC_128BIT_12ROUND(A, KEY) \
	ALCP_AESENC_128BIT_10ROUND(A, KEY)\
	A = _mm_aesenc_si128(A, KEY##_10);\
	A = _mm_aesenc_si128(A, KEY##_11);

//dec
#define ALCP_AESDEC_128BIT_12ROUND(A, KEY) \
	ALCP_AESDEC_128BIT_10ROUND(A, KEY,)\
	A = _mm_aesdec_si128(A, KEY##_10);\
	A = _mm_aesdec_si128(A, KEY##_11);

/* 14 rounds */
//enc
#define ALCP_AESENC_128BIT_14ROUND(A, KEY) \
	ALCP_AESENC_128BIT_12ROUND(A, KEY)\
	A = _mm_aesenc_si128(A, KEY##_12);\
	A = _mm_aesenc_si128(A, KEY##_13);

//dec
#define ALCP_AESDEC_128BIT_14ROUND(A, KEY) \
	ALCP_AESDEC_128BIT_12ROUND(A, KEY)\
	A = _mm_aesdec_si128(A, KEY##_12);\
	A = _mm_aesdec_si128(A, KEY##_13);

/* 10 rounds + last */
//enc
#define ALCP_AESENC_128BIT_10ROUND_LAST(A, KEY) \
	ALCP_AESENC_128BIT_10ROUND(A, KEY)\
	A = _mm_aesenclast_si128(A, KEY##_10);
//dec
#define ALCP_AESDEC_128BIT_10ROUND_LAST(A, KEY) \
	ALCP_AESDEC_128BIT_10ROUND(A, KEY)\
	A = _mm_aesdeclast_si128(A, KEY##_10);

/* 12 rounds + last */
//enc
#define ALCP_AESENC_128BIT_12ROUND_LAST(A, KEY) \
	ALCP_AESENC_128BIT_12ROUND(A, KEY)\
	A = _mm_aesenclast_si128(A, KEY##_12);

//dec
#define ALCP_AESDEC_128BIT_12ROUND_LAST(A, KEY) \
	ALCP_AESDEC_128BIT_12ROUND(A, KEY)\
	A = _mm_aesdeclast_si128(A, KEY##_12);

/* 14 rounds + last */
#define ALCP_AESENC_128BIT_14ROUND_LAST(A, KEY) \
	ALCP_AESENC_128BIT_14ROUND(A, KEY)\
	A = _mm_aesenclast_si128(A, KEY##_14);

#define ALCP_AESDEC_128BIT_14ROUND_LAST(A, KEY) \
	ALCP_AESDEC_128BIT_14ROUND(A, KEY)\
	A = _mm_aesdeclast_si128(A, KEY##_14);


#endif /* _INCLUDE_AES_AESNI_MACRO_HH_ */