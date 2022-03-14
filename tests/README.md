# ALCP Micro Tests

## Building

### Installing GTest

1. <code>git clone https://github.com/google/googletest.git</code>
2. <code>cd googletest/googletest</code>
3. <code>mkdir build</code>
4. <code>cd build</code>
5. <code>cmake ../ -DCMAKE_INSTALL_PREFIX=$HOME/.local</code> 
6. <code>make -j $(nproc --all)</code>
7. <code>make install</code>

### Setting Up Environment GTest

1. <code>export C_LIBRARY_PATH=$HOME/.local/include:$C_LIBRARY_PATH</code>
2. <code>export CPLUS_LIBRARY_PATH=$HOME/.local/include:$CPLUS_LIBRARY_PATH</code>
3. <code>export LD_LIBRARY_PATH=$HOME/.local/lib:$HOME/.local/lib64</code>

### Building ALCP with Testing framework

<font color=red>Note: Depeding on multilib(x86_64) or singlelib(amd64) setup, gtest may install in $HOME/local/lib or $HOME/local/lib64 respectively so please do change below line number 3 to use lib64 if you use singlelib (amd64)</font>

1. <code>git clone [alcp-crypto git url here]</code>
2. <code>cd alcp-crypto</code>
3. <code>cmake -B build -DALCP_ENABLE_EXAMPLES=ON -DALCP_ENABLE_TESTS=ON -DGTEST_LIBRARY=$HOME/.local/lib -DGTEST_MAIN_LIBRARY=$HOME/.local/lib -DGTEST_INCLUDE_DIR=$HOME/.local/include</code>
4. <code>cmake --build build</code>

## AES

### Executing Tests

After building ALCP, there should be binary files with name aocl-crypto/build/tests/cipher/aes\_\<aes\_mode\>\_kat. These executables expect the csv files to be located in the present working directory. CMAKE is already configured to symlink csv files to root build directory and also tests/cipher. When running these tests, please ensure you do have appropriate csv fille in the present directory.

To run tests with verbose mode (prints also success)

1. <code>cd aocl-crypto/build</code>
2. <code>./tests/cipher/aes_cbc_kat -v</code>
3. <code>./tests/cipher/aes_cfb_kat -v</code>
4. <code>./tests/cipher/aes_ctr_kat -v</code>
5. <code>./tests/cipher/aes_ofb_kat -v</code>

#### Selecting tests

To select tests, you can always use --gtest_filter.

Example filtering just 128 bit keysize tests.

​	 <code>./tests/cipher/aes\_\<aes\_mode\>\_kat --gtest_filter="\*128.\*" -v</code>

Always you can use <code>--help</code> to know all the command line arguments which can be given to the executable.

### Testing Datasets

Datasets are located in directory <code>alcp-crypto/tests/cipher/dataset/</code>. File name should be dataset_\<aes\_mode\>.csv. Order of elements are mentioned in line number 1. Line number 1 is always ignored, please forbid form deleting that line.

