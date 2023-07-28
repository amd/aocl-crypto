#!/usr/bin/env bash
# Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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

# TODO: Add verbose mode and scilent mode, this script will spit a lot of output.

# Clean
if [ -d assemble ]; then
    rm -rf assemble
fi

# Global Var
CPUID_LOC=$1
DEBUG=$2
ARGN=$#

# FIXME Propagate from cmake not working!
if [ -f libalcp.a ]; then
    DEBUG=""
    ARGN=1
else
    DEBUG="DEBUG"
    ARGN=2
fi
# END FIXME

# ALCP STATIC LIB LIST
alcp_libs=(
    libalcp
    libarch_avx2
    libarch_zen
    libarch_zen3
    libarch_zen4
)

# Bailout function
exit_err(){
    if [ $? -ne 0 ]; then
        if [ $# -eq 1 ]; then
            >&2 echo ERROR: $1
        fi
        exit -1
    fi
}

# Create directories
if [ ! -d assemble ]; then
    mkdir assemble
    exit_err assmeble
fi

if [ ! -d assemble/alcp ]; then
    mkdir assemble/alcp
    exit_err alcp
fi

if [ ! -d assemble/alci ]; then
    mkdir assemble/alci
    exit_err alci
fi

pushd .

# Extract ALCP Libs
cd assemble/alcp

# Take Every ALCP LIB and extract it
for i in "${alcp_libs[@]}"; do
    mkdir $i
    cd $i
    LIB=""

    # Lookout for debug sufix
    if [ $ARGN -eq 2 ]; then
        LIB=../../"$i"_"$DEBUG".a
    else
        LIB=../../"$i".a
    fi
    # echo ../$LIB
    if [ ! -f ../$LIB ]; then
        >&2 echo ../$LIB not found!
        exit -1
    fi

    # Handle Duplicates
    which 7z
    exit_err "7z not found in the system. Please install and re-run make\!"
    7z e -aou ../$LIB
    # ar -x ../$LIB

    # Prefix rename .o files to prevent duplicates
    for file in *.o; do
        mv "$file" "$i"_"$file"
    done

    cd ../
done

popd
pushd .

# Extract CPUID Libs
cd assemble/alci

# Find CPUID, otherwise bailout
LIB=$CPUID_LOC
if [ ! -f $LIB ]; then
    >&2 echo $LIB not found!
    exit -1
fi

ar -x $LIB

popd
pushd .

# Assemble all the libs into single
cd assemble

# clean up unwanted files
find $PWD -name "*.txt" -exec rm {} \;

# archive
ar -crs ../libalcp_static.a */*/* */*.o

popd

# Cleanup
# rm -rf assemble
