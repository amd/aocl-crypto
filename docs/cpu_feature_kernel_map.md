# ALCP CPU Feature Requirements & Kernel Dispatch Map

This document describes the CPU feature requirements and kernel dispatch logic for each algorithm in ALCP.

## Architecture Levels

| Level | Enum Value | Key Features | AMD CPUs |
|-------|------------|--------------|----------|
| **eReference** | 0 | No SIMD optimizations | Fallback only |
| **eZen** | 1 | AVX2, SSE3, AESNI (+ ADX/BMI2 for some algorithms) | Zen1, Zen2 |
| **eZen3** | 2 | + VAES (256-bit) | Zen3 |
| **eZen4** | 3 | + AVX512 (F, DQ, BW, IFMA, VL), VAES512 | Zen4 |
| **eZen5** | 4 | + AVX512 VP2INTERSECT | Zen5 |

**Note:** Not all algorithms require all features. See per-algorithm requirements below.

## Algorithm → Feature → Kernel Mapping

### 🔐 AES Cipher (CBC, CTR, GCM, XTS, CFB, OFB, CCM, SIV, ChaCha20)

| Arch Level | CPU Features | Kernel / Implementation |
|------------|--------------|-------------------------|
| eZen | AESNI + AVX2 | aesni::* (128-bit ops) |
| eZen3 | VAES + AVX2 | vaes::* (256-bit vectorized) |
| eZen4 | VAES + AVX512(F,DQ,BW,VL) | vaes512::* (512-bit vector) |


**Dispatch Location:** `lib/cipher/cipher.cc`
```cpp
// Recommended: Use algorithm-specific arch level
CpuArchLevel arch = CpuId::getCachedArchLevel(AlgorithmType::eCipher);
// Dispatches to appropriate kernel based on arch level
```

---

### #️⃣ SHA256 / SHA224

| Priority | CPU Features | Kernel / Implementation |
|----------|--------------|-------------------------|
| PRIMARY | SHA-NI | shani::ShaUpdate256() |
| FALLBACK | AVX2 (disabled) | avx2::ShaUpdate256() |
| REFERENCE | None | Software implementation |

**Note:** AVX2 fallback is deliberately disabled due to poor performance compared to SHA-NI.

**Dispatch Location:** `lib/digest/sha256.cc`
```cpp
static bool shani_available = CpuId::cpuHasShani();
if (shani_available) {
    return shani::ShaUpdate256(...);
}
```

---

### #️⃣ SHA512 / SHA384

| Arch Level | CPU Features | Kernel / Implementation |
|------------|--------------|-------------------------|
| eZen | AVX2 + SSE3 | avx2::ShaUpdate512() |
| eZen3 | AVX2 + VAES | zen3::ShaUpdate512() |
| eZen4 | AVX512(F,DQ,BW,IFMA,VL) | zen4::ShaUpdate512() |
| Reference | None | Software implementation |

**Note:** For AOCC compiler, Zen4 uses zen3 kernel due to better performance.

**Dispatch Location:** `lib/digest/sha512.cc`
```cpp
// Recommended: Use SHA512-specific arch level
static CpuArchLevel archLevel = CpuId::getCachedArchLevel(AlgorithmType::eSha2_512);
switch (archLevel) {
    case CpuArchLevel::eZen4: return zen4::ShaUpdate512(...);
    case CpuArchLevel::eZen3: return zen3::ShaUpdate512(...);
    case CpuArchLevel::eZen:  return avx2::ShaUpdate512(...);
}
```

---

### 🔑 RSA (1024/2048-bit)

| Arch Level | CPU Features | Kernel / Implementation |
|------------|--------------|-------------------------|
| eZen | ADX + BMI2 | zen::archEncryptPublic<>() |
| eZen3 | ADX + BMI2 | zen3::archEncryptPublic<>() |
| eZen4 | ADX + BMI2 + AVX512-IFMA | zen4::archEncryptPublic<>() |

**Key Sizes:** 1024-bit (KEY_SIZE_1024), 2048-bit (KEY_SIZE_2048)

**Dispatch Location:** `lib/rsa/rsa.cc`
```cpp
// Recommended: Use RSA-specific arch level (requires IFMA for Zen4, not VAES)
static CpuArchLevel archLevel = CpuId::getCachedArchLevel(AlgorithmType::eRsa);
switch (archLevel) {
    case CpuArchLevel::eZen4: zen4::archEncryptPublic<KEY_SIZE_2048>(...);
    case CpuArchLevel::eZen3: zen3::archEncryptPublic<KEY_SIZE_2048>(...);
    case CpuArchLevel::eZen:  zen::archEncryptPublic<KEY_SIZE_2048>(...);
}
```

---

### 🌀 SHA3 / SHAKE (SHA3-224/256/384/512, SHAKE128/256)

| Arch Level | CPU Features | Kernel / Implementation |
|------------|--------------|-------------------------|
| eZen | AVX2 | zen::Sha3Update() |
| eZen3 | AVX2 + VAES | zen3::Sha3Update() |
| eZen4 | AVX512(F,DQ,BW,IFMA,VL) | zen4::Sha3Update() |
| eZen5 | AVX512Full + VP2INTERSECT | zen3 (Clang) / zen4 (other) |
| Reference | None | Software implementation |

**Note:** For Zen5, the kernel selection is compiler-dependent:
- **Clang**: Uses `zen3::Sha3Update()` for better performance
- **Other compilers** (GCC, AOCC): Uses `zen4::Sha3Update()`

**Dispatch Location:** `lib/digest/sha3.cc`
```cpp
// Recommended: Use SHA3-specific arch level
static CpuArchLevel archLevel = CpuId::getCachedArchLevel(AlgorithmType::eSha3);
switch (archLevel) {
    case CpuArchLevel::eZen5:
#ifdef COMPILER_IS_CLANG
        return zen3::Sha3Update(...);  // Clang: zen3 kernel
#else
        return zen4::Sha3Update(...);  // Other: zen4 kernel
#endif
    case CpuArchLevel::eZen4: return zen4::Sha3Update(...);
    case CpuArchLevel::eZen3: return zen3::Sha3Update(...);
    case CpuArchLevel::eZen:  return zen::Sha3Update(...);
}
```

---

### 🔏 Poly1305 (MAC)

| Arch Level | CPU Features | Kernel / Implementation |
|------------|--------------|-------------------------|
| eZen | AVX2 | reference::Poly1305Ref() |
| eZen3 | AVX2 | reference::Poly1305Ref() |
| eZen4 | AVX512(F,DQ,BW,IFMA) | zen4::poly1305_*_radix44() |

**Dispatch Condition:** `CpuId::cpuHasAvx512(F,DQ,BW,IFMA)` for Zen4 path

**Dispatch Location:** `lib/mac/poly1305.cc`
```cpp
// Recommended: Use Poly1305-specific arch level
// Returns eZen4 if AVX512Base available, otherwise eZen/eReference
static CpuArchLevel archLevel = CpuId::getCachedArchLevel(AlgorithmType::ePoly1305);
if (archLevel >= CpuArchLevel::eZen4) {
    zen4::poly1305_init_radix44(state, key);
} else {
    poly1305_impl->init(key, keyLen);  // Reference
}
```

---

### 🔐 X25519 (ECDH)

| Arch Level | CPU Features | Kernel / Implementation |
|------------|--------------|-------------------------|
| eZen | ADX + BMI2 + AVX2 | avx2::alcpScalarMulX25519() |
| eZen3 | ADX + BMI2 + AVX2 + VAES | zen3::alcpScalarMulX25519() |
| eZen4 | AVX512(F,DQ,BW,IFMA,VL) | zen4::alcpScalarMulX25519() |

**Note:** X25519 has different implementations:
- **Zen4**: Uses `radix51bit` (AVX512)
- **Zen/Zen3**: Uses `radix64bit` (ADX/BMI2)

**Dispatch Location:** `lib/ec/ecdh_x25519.cc`
```cpp
// Recommended: Use X25519-specific arch level
static CpuArchLevel archLevel = CpuId::getCachedArchLevel(AlgorithmType::eX25519);
if (archLevel < CpuArchLevel::eZen) {
    return status::NotAvailable("Not supported due to missing instruction set");
}
switch (archLevel) {
    case CpuArchLevel::eZen4: zen4::alcpScalarMulX25519(...); break;
    case CpuArchLevel::eZen3: zen3::alcpScalarMulX25519(...); break;
    case CpuArchLevel::eZen:  avx2::alcpScalarMulX25519(...); break;
}
```

---

## Per-Algorithm Architecture Level API

Different algorithms have different CPU feature requirements. The `getArchLevel()` function now accepts an `AlgorithmType` parameter for accurate per-algorithm dispatch.

### AlgorithmType Enum

```cpp
enum class AlgorithmType
{
    eCipher,   // AES modes: AESNI+AVX2 → VAES+AVX2 → VAES+AVX512
    eRsa,      // ADX+BMI2 → ADX+BMI2 → ADX+BMI2+IFMA
    ePoly1305, // AVX2 → AVX2 → AVX512(F,DQ,BW,IFMA)
    eX25519,   // ADX+BMI2+AVX2 → ADX+BMI2+VAES → AVX512
    eSha2_256, // SHA-NI based (orthogonal)
    eSha2_512, // AVX2+SSE3 → VAES+AVX2 → AVX512
    eSha3,     // AVX2 → VAES+AVX2 → AVX512
    eDefault,  // Backward compatibility (original behavior)
};
```

### Usage

```cpp
// Per-algorithm dispatch (recommended)
CpuArchLevel cipherArch = CpuId::getCachedArchLevel(AlgorithmType::eCipher);
CpuArchLevel rsaArch = CpuId::getCachedArchLevel(AlgorithmType::eRsa);

// Backward compatible (uses eDefault - original blanket check)
CpuArchLevel defaultArch = CpuId::getCachedArchLevel();
```

### Per-Algorithm Feature Requirements

| AlgorithmType | eZen Requirements | eZen3 Requirements | eZen4 Requirements | eZen5 Requirements |
|---------------|-------------------|-------------------|-------------------|-------------------|
| **eCipher** | AESNI + AVX2 | VAES + AVX2 | AVX512(F,DQ,BW,VL) + VAES | AVX512(F,DQ,BW,VL) + VAES |
| **eRsa** | ADX + BMI2 + AVX2 | ADX + BMI2 + AVX2 | ADX + BMI2 + IFMA | ADX + BMI2 + IFMA |
| **ePoly1305** | AVX2 | AVX2 | AVX512(F,DQ,BW,IFMA) | AVX512(F,DQ,BW,IFMA) |
| **eX25519** | ADX + BMI2 + AVX2 | ADX + BMI2 + AVX2 + VAES | AVX512Full | AVX512Full |
| **eSha2_256** | SHA-NI | SHA-NI | SHA-NI | SHA-NI |
| **eSha2_512** | AVX2 + SSE3 | VAES + AVX2 | AVX512Full | AVX512Full |
| **eSha3** | AVX2 | VAES + AVX2 | AVX512Full | AVX512Full + VP2INTERSECT |
| **eDefault** | ADX + BMI2 + AVX2 + AESNI | VAES + ADX + BMI2 + AVX2 | AVX512Full + VAES | AVX512Full + VAES |

**Key Differences from Blanket Check:**
- **RSA** requires ADX/BMI2 for big integer arithmetic
- **X25519 Zen4** uses AVX512 radix51bit implementation
- **X25519 Zen/Zen3** requires ADX/BMI2 for radix64bit implementation
- **Poly1305** only needs AVX512(F,DQ,BW,IFMA) for Zen4 optimization

---

## Architecture Detection Flow (Default/Legacy)

The following flow applies to `AlgorithmType::eDefault` (backward compatible mode):

```
┌──────────────────────────────┐     NO     ┌──────────────────────────────┐
│ cpuHasAvx512(F,DQ,BW,IFMA,VL)│──────────▶│ cpuHasVaes() &&              │
│ && cpuHasVaes()              │           │ cpuHasAdx() && cpuHasAvx2()  │
│ (F+DQ+BW+IFMA+VL+VAES)       │           │ && cpuHasBmi2()              │
└──────────┬───────────────────┘           └──────────┬───────────────────┘
           │ YES                                      │ YES      │ NO
           ▼                                          ▼          ▼
     ┌──────────┐                              ┌──────────┐  ┌───────────────────────┐
     │  eZen4   │                              │  eZen3   │  │ cpuHasAdx() &&        │
     └──────────┘                              └──────────┘  │ cpuHasAvx2() &&       │
                                                             │ cpuHasBmi2() &&       │
                                                             │ cpuHasAesni()         │
                                                             └──────────┬────────────┘
                                                                        │ YES    │ NO
                                                                        ▼        ▼
                                                                  ┌─────────┐ ┌────────────┐
                                                                  │  eZen   │ │ eReference │
                                                                  └─────────┘ └────────────┘
```

**Implementation:** `lib/utils/cpuid.cc` → `CpuId::getArchLevel(AlgorithmType)`

### ISA Feature Checks

| Check | Features | Used By |
|-------|----------|---------|
| AVX512 Full | `cpuHasAvx512(F,DQ,BW,IFMA,VL)` | SHA2-512, SHA3, X25519 (Zen4) |
| AVX512 Cipher | `cpuHasAvx512(F,DQ,BW,VL)` + `cpuHasVaes()` | Ciphers (Zen4) |
| AVX512 Poly | `cpuHasAvx512(F,DQ,BW,IFMA)` | Poly1305 (Zen4) |
| ADX/BMI2 | `cpuHasAdx()` + `cpuHasBmi2()` | RSA, X25519 (Zen/Zen3) |

---

## Environment Override

Force a specific architecture level at runtime. This can only **downgrade** the kernel level — setting a higher level on hardware that doesn't support it has no effect (the actual kernel level is still determined by ISA feature detection).

This override is a test and benchmark facility. It is compiled in only when the project is configured with `ALCP_ENABLE_TESTS=ON`. Release and RTE packages do not read the variable at all and silently ignore it, always dispatching on the detected hardware.

```bash
# Force max Zen4 kernels (disables VP2INTERSECT)
export AOCL_ENABLE_INSTRUCTION=ZEN4

# Available values: ZEN, ZEN1, ZEN2, ZEN3, ZEN4, ZEN5
```

| Value | Effect |
|-------|--------|
| `ZEN` / `ZEN1` | Disables AVX512 and VAES — forces max eZen (Zen1/Zen2) kernel level |
| `ZEN2` | Same as ZEN/ZEN1 (Zen2 shares the eZen kernel level) |
| `ZEN3` | Disables AVX512 — forces max eZen3 kernel level (256-bit VAES) |
| `ZEN4` | Disables VP2INTERSECT — forces max eZen4 kernel level |
| `ZEN5` | No features disabled — native CPU detection is used (no-op) |

> **Note:** In builds where the override is compiled in, passing an invalid value will cause the process to exit with an error.

---

## Source File Locations

| Algorithm | Dispatch File | Kernel Directories |
|-----------|--------------|-------------------|
| Cipher (AES) | `lib/cipher/cipher.cc` | `lib/arch/{avx2,zen3,zen4}/vaes*.cc`, `aesni*.cc` |
| ChaCha20 | `lib/cipher/chacha20.cc` | `lib/arch/zen4/chacha20.cc` |
| SHA256 | `lib/digest/sha256.cc` | `lib/arch/avx2/shani.cc` |
| SHA512 | `lib/digest/sha512.cc` | `lib/arch/{avx2,zen3,zen4}/sha*_512*.cc` |
| SHA3 | `lib/digest/sha3.cc` | `lib/arch/{zen3,zen4}/sha3*.cc` |
| RSA | `lib/rsa/rsa.cc` | `lib/arch/{zen,zen3,zen4}/rsa.cc` |
| Poly1305 | `lib/mac/poly1305.cc` | `lib/arch/zen4/poly1305.cc` |
| X25519 | `lib/ec/ecdh_x25519.cc` | `lib/arch/{avx2,zen3,zen4}/x25519.cc` |

---

## Visual Diagram

See `cpu_feature_kernel_map.svg` for a graphical representation of this mapping.
