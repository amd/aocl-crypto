# ALCP Micro Tests

### Building ALCP with Testing framework

KAT (Known Answer Test) test data is stored in git-lfs. Install git-lfs before
cloning so the CSV datasets are downloaded automatically:

1. Install git-lfs: https://git-lfs.github.com (e.g. `$ sudo apt install git-lfs`)
2. `$ git lfs install`
3. `$ git clone [alcp-crypto git url here]`
4. `$ cd alcp-crypto`

> **Already cloned without git-lfs?** Run `git lfs install && git lfs pull` from
> inside the repository to fetch the missing test data files.

5. `$ cmake -B build -DALCP_ENABLE_EXAMPLES=ON -DALCP_ENABLE_TESTS=ON -DCMAKE_BUILD_TYPE=Release`
6. `$ cmake --build build`

> **Note:** To include IPP, please define `-DENABLE_TESTS_IPP_API=ON -DIPP_INSTALL_DIR=/path/to/ipp_prefix` in step 5.<br>
> **Note:** To include OpenSSL, please define `-DENABLE_TESTS_OPENSSL_API=ON -DOPENSSL_INSTALL_DIR=/path/to/openssl_prefix` in step 5.

## AES

### Executing Tests

##### With Make

1. `$ cd aocl-crypto/build`
2. `$ make test` or faster `$ CTEST_PARALLEL_LEVEL=$(nproc --all) make test`

##### Manual

After building AOCL-Cryptography library and tests, there should be binary files with name aocl-crypto/build/tests/cipher/test\_\<aes\_mode\>\_kat. These executables expect the csv files to be located in the present working directory. CMAKE is already configured to symlink csv files to root build directory and also tests/cipher. When running these tests, please ensure you do have appropriate csv file in the present directory.

To run tests with verbose mode for different modules

1.   `$ cd aocl-crypto/build`

2.  `$ ./tests/cipher/test_cbc_kat -v`

3.  `$ ./tests/cipher/test_cfb_kat -v`

4.  `$ ./tests/cipher/test_ctr_kat -v`

5.  `$ ./tests/cipher/test_ofb_kat -v`

6.  `$ ./tests/digest/test_digest_kat -v`

7.  `$ ./tests/hmac/test_hmac_kat -v`

##### Additional (Running Cross tests vs OpenSSL)

1. `$ cd aocl-crypto/build`

2. `$ ./tests/cipher/test_cbc_cross -o` 

3.  `$ ./tests/cipher/test_cfb_cross -o`

4.  `$ ./tests/cipher/test_ctr_cross -o`

5.  `$ ./tests/cipher/test_ofb_cross -o`

6. `$ ./tests/digest/test_digest_cross -o`

#### Selecting tests

To select tests, you can always use --gtest_filter.

Example filtering just 128 bit keysize tests.

​	`$ ./tests/cipher/test_\<aes\_mode\>_kat --gtest_filter="\*128.\*" -v`

Example filtering just additional small tests.

​    `$ ./tests/cipher/test_<aes\_mode\>_cross --gtest_filter="\*SMALL" -o `

Always you can use `--help` to know all the command line arguments which can be given to the executable.

#### Using IPP

For using IPP just specify `-i` command line argument instead of `-o`.

#### Using OpenSSL

For using OpenSSL just specify `-o` command line argument.

### Testing Datasets

Datasets (eg: cipher) are located in directory `alcp-crypto/tests/cipher/test_data/`. File name should be dataset_\<aes\_mode\>.csv. Order of elements are mentioned in line number 1. Line number 1 is always ignored, please forbid from deleting that line.

### Fuzz Tests

Fuzz tests require Clang (libFuzzer is not supported with GCC):

```sh
$ export CC=clang
$ export CXX=clang++
```

Build with fuzz tests enabled:

```sh
$ cmake -B build -DALCP_ENABLE_FUZZ_TESTS=ON [other flags...]
$ cmake --build build
```

Fuzz tests are automatically registered with CTest under the `fuzz` label and
are excluded from a plain `ctest` run. Crash artifacts are written to
`build/fuzz_corpus/`.

Run all fuzz tests in parallel:

```sh
$ ctest --test-dir build -L fuzz -j$(nproc)
```

Default libFuzzer flags are `-rss_limit_mb=32768 -detect_leaks=0 -max_total_time=30`.
Override individual flags at run time via `ALCP_CTEST_FUZZ_ARGS`:

```sh
# Run with a longer time budget
$ ALCP_CTEST_FUZZ_ARGS="-max_total_time=120" ctest --test-dir build -L fuzz -j$(nproc)

# Combine overrides
$ ALCP_CTEST_FUZZ_ARGS="-max_total_time=120 -rss_limit_mb=65536" ctest --test-dir build -L fuzz -j$(nproc)
```

To run an individual target:

```sh
$ ./build/tests/Fuzz/Digest/test_fuzz_digest_sha2_256
```

### Force runtime CPU Architecture
To force a specific CPU architecture level at runtime, use the environment variable `AOCL_ENABLE_INSTRUCTION` before running the executable.
Supported values: `ZEN`, `ZEN1`, `ZEN2`, `ZEN3`, `ZEN4`, `ZEN5` (ZEN and ZEN1 are equivalent).

> **Note:** This can only **downgrade** the kernel level — setting a higher level on lower hardware has no effect.
> An invalid value will cause the process to exit with an error.
> For detailed per-algorithm dispatch behavior, see [CPU Feature Kernel Map](../docs/cpu_feature_kernel_map.md).

```sh
$ AOCL_ENABLE_INSTRUCTION=ZEN3 ./tests/cipher/test_gcm_kat
```
