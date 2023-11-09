# Build and run AOCL-Cryptography examples

The example snippets can be found in the source code and the package under `aocl-crypto/examples/`

**An example [snippet](https://github.com/amd/aocl-crypto/blob/main/examples/cipher/aes-cfb.c) for AES CFB Cipher**

To compile AOCL-Cryptography with examples, refer to
    - [ Linux ](md_Combine_build.html#md_BUILD)
    - [ Windows ](md_Combine_build.html#md_BUILD_Windows)

The examples executables for each module will be generated in aocl-crypto/build/examples/

**NOTE:**  
The AOCL-Cryptography has a dependency on OpenSSL libcrypto library and also AOCL Utils library.
Please make sure the below paths are added to the environment variables 

[//]: # (There are spaces intentionaly left to break line below)

**Execute Examples On Linux OS**  
Export the following paths:  

```bash
export LIBRARY_PATH=\<path to openssl crypto lib\>:$LIBRARY_PATH;
export LIBRARY_PATH=\<path to AOCL Utils lib\>:$LIBRARY_PATH;
export LD_LIBRARY_PATH=\<path to openssl crypto lib\>:$LD_LIBRARY_PATH;
export LD_LIBRARY_PATH=\<path to AOCL Utils lib\>:$LD_LIBRARY_PATH;
```

Now to run any executable:  
`./examples/cipher/aes-cfb`


**Execute Examples On Windows OS**  
Run the script:  
`.\scripts\Set_Env_Path.bat`


Now to run any executable:  
`.\examples\cipher\release\aes-cfb.exe`

## Build and Run AOCL-Cryptography and examples from the source code (Linux)

Below shell script is an example of how you can clone repositories, compile and execute example.

```bash
#!/usr/bin/env bash

# This file is supposed to be a guide to compile aocl-crypto with examples 
# from source.
# It should only require minimal interaction from user.
# All functions in this file should be straight forward and minimal.
# For detailed info please take a look at BUILD.md located in the root of 
# AOCL-Cryptography source code directory.

# Global Variables to be modifed depending on repo location
AOCL_CRYPTO_REPO="https://github.com/amd/aocl-crypto.git"
AOCL_UTILS_REPO="https://github.com/amd/aocl-utils.git"
AOCL_BRANCH="amd-main"

# Function to check if lsb_release is installed
ensure_lsb_release(){
    type lsb_release > /dev/null
    if [ $? -ne 0 ]; then
        echo "lsb_release not found!"
        exit -1;
    else
        echo "lsb_release found"
    fi
}

# Function to check if OS is ubuntu with a specific version
detect_ubuntu(){
    lsb_release --id | grep "Ubuntu" > /dev/null
    if [ $? -eq 0 ]; then
        # Detected Ubuntu
        echo "Detected Ubuntu"
        lsb_release --release | grep $1 > /dev/null
        if [ $? -eq 0 ]; then
            echo "Detected OS Release Version $1"
            return 0
        fi
    fi
    return 1 # Return error
}

# Function to exit with an error if some execution failed
quit_if_status_not_zero(){
    if [ $1 -ne 0 ]; then
        echo "Command returned error"
        exit -1 
    fi
}

# Function to install all packages, OS indipendant (eventually)
ensure_packages(){
    detect_ubuntu 22.04
    if [ $? -eq 0 ]; then
        echo "Running \"sudo apt update\""
        sudo apt update                      # Sync repository information
        quit_if_status_not_zero $?
        echo "Running \"sudo install git\""
        sudo apt install git                 # To clone github repositories
        quit_if_status_not_zero $?
        echo "Running \"sudo install libssl-dev\""
        sudo apt install libssl-dev          # For openssl
        quit_if_status_not_zero $?
        echo "Running \"sudo install make\""
        sudo apt install make                # Build system
        quit_if_status_not_zero $?
        echo "Running \"sudo install cmake\""
        sudo apt install cmake               # Build system generator
        quit_if_status_not_zero $?
        echo "Running \"sudo install p7zip-full\""
        sudo apt install p7zip-full          # Re-archive static libs
        quit_if_status_not_zero $?
        echo "Running \"sudo install gcc-12 g++-12\""
        sudo apt install gcc-12 g++-12       # Compiler
        quit_if_status_not_zero $?
        return 0
    fi
    # detect_rhel 8
    # if [ $? -eq 1 ]; then
    #    sudo yum install...
    #    ...
    #    return 1
    echo "OS support check failed!"
    exit -1
}

# Function to make sure what this script writes don't already exist
ensure_no_directory_conflict(){
    # Check if aocl-crypto directory already exists
    if [[ -d aocl-crypto ||  -f aocl-crypto ]]; then
        echo "aocl-crypto exists!"
        echo "Please run \"rm -rf aocl-crypto\""
        exit -1
    fi
    # Check if aocl-utils directory already exists
    if [[ -d aocl-utils || -f aocl-utils ]]; then
        echo "aocl-utils exists!"
        echo "Please run \"rm -rf aocl-utils\""
        exit -1
    fi
}

# Function to clone the repo both aocl-utils and aocl-crypto.
clone_repos(){

    # Clone AOCL-Cryptography
    echo "Running \"git clone $AOCL_CRYPTO_REPO -b $AOCL_BRANCH\""
    git clone $AOCL_CRYPTO_REPO -b $AOCL_BRANCH
    quit_if_status_not_zero $?

    sleep 1

    # Clone AOCL-Utils
    echo "Running \"git clone $AOCL_UTILS_REPO -b $AOCL_BRANCH\""
    git clone $AOCL_UTILS_REPO -b $AOCL_BRANCH
    quit_if_status_not_zero $?

}

# Function to build aocl-utils with minimal configuration
compile_aocl_utils(){

    pushd .
    echo "cd into aocl-utils"
    cd aocl-utils
    echo "creating build directory"
    mkdir build
    echo "cd into build directory"
    cd build
    echo "Setting GCC-12 as the compiler"
    export CC=gcc-12; export CXX=g++-12
    echo "Running \"cmake ../ -DCMAKE_INSTALL_PREFIX=$PWD/install -DCMAKE_BUILD_TYPE=Release -DALCI_DOCS=OFF\""
    cmake ../ -DCMAKE_INSTALL_PREFIX=install -DCMAKE_BUILD_TYPE=Release -DALCI_DOCS=OFF
    echo "Running \"make -j $(nproc --all)\""
    make -j $(nproc --all)
    quit_if_status_not_zero $?
    make install
    quit_if_status_not_zero $?
    popd

}

# Function to build aocl-crypto with minimal configuration
compile_aocl_crypto(){
    
    pushd .
    echo "cd into aocl-crypto"
    cd aocl-crypto
    echo "creating build directory"
    mkdir build
    echo "cd into build directory"
    cd build
    echo "Setting GCC-12 as the compiler"
    export CC=gcc-12; export CXX=g++-12
    echo "Running \"cmake ../ -DALCP_ENABLE_EXAMPLES=ON \
-DOPENSSL_INSTALL_DIR=/usr \
-DCMAKE_INSTALL_PREFIX=$PWD/install \
-DENABLE_AOCL_UTILS=ON \
-DAOCL_UTILS_INSTALL_DIR=$PWD/../../aocl-utils/build/install\""
    cmake ../ -DALCP_ENABLE_EXAMPLES=ON \
              -DOPENSSL_INSTALL_DIR=/usr \
              -DCMAKE_INSTALL_PREFIX=$PWD/install \
              -DENABLE_AOCL_UTILS=ON \
              -DAOCL_UTILS_INSTALL_DIR=$PWD/../../aocl-utils/build/install
    echo "Running \"make -j $(nproc --all)\""
    make -j $(nproc --all)
    quit_if_status_not_zero $?
    make install
    quit_if_status_not_zero $?
    popd

}

# Function to show how to execute an example properly
run_example_cfb(){

    pushd .
    echo "Exporting library paths for loader"
    # Update loader with aocl-utils lib
    export LD_LIBRARY_PATH=$PWD/aocl-utils/build/install/lib:$PWD/aocl-utils/build/install/lib64:$LD_LIBRARY_PATH
    # Update loader with aocl-crypto lib
    export LD_LIBRARY_PATH=$PWD/aocl-crypto/build/install/lib:$PWD/aocl-crypto/build/install/lib64:$LD_LIBRARY_PATH
    echo "cd into aocl-crypto/build"
    cd aocl-crypto/build
    echo "Executing \"$PWD/examples/cipher/aes-cfb\""
    $PWD/examples/cipher/aes-cfb
    quit_if_status_not_zero $?
    echo "Executed Successfully!, output above"
    popd

}

# Make sure we dont destroy anything
ensure_no_directory_conflict
# Make sure we can detect the OS
ensure_lsb_release
# Make sure all the needed packages (dependancies) are installed
ensure_packages
# Clone Utils and Crypto
clone_repos
# Build Utils and Install it into a prefix inside build directory
compile_aocl_utils
# Build Crypto and Install it into a prefix inside the build directory
compile_aocl_crypto
# Run an example to show that, its indeed working.
run_example_cfb

```

## Build and Run AOCL-Cryptography examples from the AOCL Crypto release package (Linux)

**Download the tar package from https://www.amd.com/en/developer/aocl/cryptography.html (under the downloads section)**

**NOTE:**  
The AOCL-Cryptography library has a dependency on OpenSSL libcrypto library and also AOCL Utils library.
Please make sure these library paths are added to the environment variables LIBRARY_PATH and LD_LIBRARY_PATH

Also, please ensure the variable OPENSSL_INSTALL_DIR is set.  
`export OPENSSL_INSTALL_DIR=\<path to openssl installation/lib64/\>;`


**To run the examples linking to AOCL-Cryptography shared library:**  

```bash
# Ensure OpenSSL is available with linker
export LIBRARY_PATH=/path/to/openssl_install/lib:$LIBRARY_PATH; 
# Ensure AOCL-Utils is available with linker
export LIBRARY_PATH=/path/to/aocl-utils/lib:$LIBRARY_PATH; 
# Ensure OpenSSL is available with loader
export LD_LIBRARY_PATH=/path/to/openssl_install/lib:$LD_LIBRARY_PATH; 
# Ensure AOCL-Utils is available with loader
export LD_LIBRARY_PATH=/path/to/aocl-utils/lib:$LD_LIBRARY_PATH; 
cd amd-crypto;
make;
```


**To run the examples linking to AOCL-Cryptography static library:**  

```bash
cd amd-crypto;
make LIB_TYPE=static;
```


## To compile and run the examples from the AOCL-Cryptography installed directory:  
```bash
cd /path/to/amd-crypto;
export C_INCLUDE_PATH=$PWD/include:$C_INCLUDE_PATH;
make -j;
```

**Run the Examples:**  
`./bin/cipher/aes-cfb;`
