# ALCP Micro Tests

### Building ALCP with Testing framework

1. <code>git clone [alcp-crypto git url here]</code>
2. <code>cd alcp-crypto</code>
3. <code>cmake -B build -DALCP_ENABLE_EXAMPLES=ON -DALCP_ENABLE_TESTS=ON -DCMAKE_BUILD_TYPE=Release</code>
4. <code>cmake --build build</code>

<font color="red"> Note - To include IPP, please define <code>-DENABLE_TESTS_IPP_API=ON -DIPP_INSTALL_DIR=/path/to/ipp_prefix</code> in step 3.</font><br>
<font color="red"> Note - To include OpenSSL, please define <code>-DOPENSSL_INSTALL_DIR=/path/to/openssl_prefix</code> in step 3.</font>

## AES

### Executing Tests

After building ALCP, there should be binary files with name aocl-crypto/build/tests/cipher/aes\_\<aes\_mode\>\_kat. These executables expect the csv files to be located in the present working directory. CMAKE is already configured to symlink csv files to root build directory and also tests/cipher. When running these tests, please ensure you do have appropriate csv fille in the present directory.

To run tests with verbose mode (prints also success)

1. <code>cd aocl-crypto/build</code>
2. <code>./tests/cipher/aes_cbc_kat -v</code>
3. <code>./tests/cipher/aes_cfb_kat -v</code>
4. <code>./tests/cipher/aes_ctr_kat -v</code>
5. <code>./tests/cipher/aes_ofb_kat -v</code>
6. <code>./tests/digests/test_digest -v</code>

#### Selecting tests

To select tests, you can always use --gtest_filter.

Example filtering just 128 bit keysize tests.

​	 <code>./tests/cipher/aes\_\<aes\_mode\>\_kat --gtest_filter="\*128.\*" -v</code>

Always you can use <code>--help</code> to know all the command line arguments which can be given to the executable.

#### Using IPP

For using IPP just specify <code>-i</code> command line argument.

#### Using OpenSSL

For using OpenSSL just specify <code>-o</code> command line argument.

### Testing Datasets

Datasets are located in directory <code>alcp-crypto/tests/cipher/dataset/</code>. File name should be dataset_\<aes\_mode\>.csv. Order of elements are mentioned in line number 1. Line number 1 is always ignored, please forbid form deleting that line.
