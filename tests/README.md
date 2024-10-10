# ALCP Micro Tests

### Building ALCP with Testing framework

1. `$ git clone [alcp-crypto git url here]`
2. `$ cd alcp-crypto`
3. `$ cmake -B build -DALCP_ENABLE_EXAMPLES=ON -DALCP_ENABLE_TESTS=ON -DCMAKE_BUILD_TYPE=Release`
4. `$ cmake --build build`

<span style="color:red"> __Note__: </span> To include IPP, please define `-DENABLE_TESTS_IPP_API=ON -DIPP_INSTALL_DIR=/path/to/ipp_prefix` in step 3.<br>
<span style="color:red"> __Note__: </span> To include OpenSSL, please define `-DENABLE_TESTS_OPENSSL_API=ON -DOPENSSL_INSTALL_DIR=/path/to/openssl_prefix` in step 3.

## AES

### Executing Tests

##### With Make

1. `$ cd aocl-crypto/build`
2. `$ make test` or faster `$ CTEST_PARALLEL_LEVEL=$(nproc --all) make test`

##### Manual

After building AOCL-Cryptography library and tests, there should be binary files with name aocl-crypto/build/tests/cipher/aes\_\<aes\_mode\>\_kat. These executables expect the csv files to be located in the present working directory. CMAKE is already configured to symlink csv files to root build directory and also tests/cipher. When running these tests, please ensure you do have appropriate csv file in the present directory.

To run tests with verbose mode for different modules

1.   `$ cd aocl-crypto/build`

2.  `$ ./tests/cipher/aes_cbc_kat -v`

3.  `$ ./tests/cipher/aes_cfb_kat -v`

4.  `$ ./tests/cipher/aes_ctr_kat -v`

5.  `$ ./tests/cipher/aes_ofb_kat -v`

6.  `$ ./tests/digests/test_digest_kat -v`

7.  `$ ./tests/hmac/test_hmac_kat -v`

##### Additional (Running Cross tests vs OpenSSL)

1. `$ cd aocl-crypto/build`

2. `$ ./tests/cipher/aes_cbc_cross -o` 

3.  `$ ./tests/cipher/aes_cfb_cross -o`

4.  `$ ./tests/cipher/aes_ctr_cross -o`

5.  `$ ./tests/cipher/aes_ofb_cross -o`

6. `$ ./tests/digest/test_digest_cross -o`

#### Selecting tests

To select tests, you can always use --gtest_filter.

Example filtering just 128 bit keysize tests.

​	`$ ./tests/cipher/aes\_\<aes\_mode\>\_kat --gtest_filter="\*128.\*" -v`

Example filtering just additional small tests.

​    `$ ./tests/cipher/aes_<aes\_mode\>_cross --gtest_filter="\*SMALL" -o `

Always you can use `--help` to know all the command line arguments which can be given to the executable.

#### Using IPP

For using IPP just specify `-i` command line argument instead of `-o`.

#### Using OpenSSL

For using OpenSSL just specify `-o` command line argument.

### Testing Datasets

Datasets (eg: cipher) are located in directory `alcp-crypto/tests/cipher/test_data/`. File name should be dataset_\<aes\_mode\>.csv. Order of elements are mentioned in line number 1. Line number 1 is always ignored, please forbid from deleting that line.

### Fuzz Tests
To enable fuzz tests set the compiler to clang 

```sh
$ export CXX=clang++
```
```sh
$ export CC=clang
```

Then build crypto library by appending the flag ALCP_ENABLE_FUZZ_TESTS=ON

In order to run the whole fuzz tests you can use run_fuzz_tests.py under the scripts directory.
```sh
$ python3 ./scripts/python/run_fuzz_tests.py ./build
```
The individual tests will be under build/tests/Fuzz directory. For example in order to run the digest sha256 fuzz test the following command could be used  `./tests/Fuzz/Digest/test_fuzz_digest_sha2_256`