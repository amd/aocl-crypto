#!/usr/bin/env bash
# Copyright (C) 2023-2025, Advanced Micro Devices. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 3. Neither the name of the copyright holder nor the names of its contributors
#    may be used to endorse or promote products derived from this software
# without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

# This file is supposed to be a guide to compile aocl-crypto with examples 
# from source.
# It should only require minimal interaction from user.
# All functions in this file should be straight forward and minimal.
# For detailed info please take a look at BUILD.md located in the root of 
# AOCL-Cryptography source code directory.

# Global Variables to be modifed depending on repo location
AOCL_CRYPTO_REPO="git@er.github.amd.com:AOCL/aocl-crypto"
AOCL_UTILS_REPO="git@github.amd.com:AOCL/aocl-utils"
AOCL_BRANCH="amd-main"

# Function to exit with an error if some execution failed
quit_if_status_not_zero(){
    if [ $1 -ne 0 ]; then
        echo "Command returned error"
        exit -1 
    fi
}

# Function to install all packages, OS indipendant (eventually)
ensure_packages(){
    detect_ubuntu 24.04
    if [ $? -eq 0 ]; then
        echo "Running \"sudo apt update\""
        sudo apt update                      # Sync repository information
        echo "Running \"apt install build-essential\""
        sudo apt install build-essential     # Basic packages to support compilation
        quit_if_status_not_zero $?
        echo "Running \"sudo install git\""
        sudo apt install git                 # To clone github repositories
        quit_if_status_not_zero $?
        echo "Running \"sudo apt install libssl-dev\""
        sudo apt install libssl-dev          # For openssl
        quit_if_status_not_zero $?
        echo "Running \"sudo apt install make\""
        sudo apt install make                # Build system
        quit_if_status_not_zero $?
        echo "Running \"sudo apt install cmake\""
        sudo apt install cmake               # Build system generator
        quit_if_status_not_zero $?
        echo "Running \"sudo apt install p7zip-full\""
        sudo apt install p7zip-full          # Re-archive static libs
        quit_if_status_not_zero $?
        echo "Running \"sudo apt install gcc-12 g++-12\""
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
    echo "Setting GCC-13 as the compiler"
    export CC=gcc-13; export CXX=g++-13
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
    echo "Setting GCC-13 as the compiler"
    export CC=gcc-13; export CXX=g++-13
    echo "Running \"cmake ../ -DALCP_ENABLE_EXAMPLES=ON \
-DOPENSSL_INSTALL_DIR=/usr \
-DCMAKE_INSTALL_PREFIX=$PWD/install \
-DENABLE_AOCL_UTILS=ON \
-DAOCL_UTILS_INSTALL_DIR=$(realpath $PWD/../../aocl-utils/build/install)\""
    cmake ../ -DALCP_ENABLE_EXAMPLES=ON \
              -DOPENSSL_INSTALL_DIR=/usr \
              -DCMAKE_INSTALL_PREFIX=$PWD/install \
              -DENABLE_AOCL_UTILS=ON \
              -DAOCL_UTILS_INSTALL_DIR=$(realpath $PWD/../../aocl-utils/build/install)
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
