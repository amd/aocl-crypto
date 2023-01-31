#!/usr/bin/env sh
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


# Framework functions
check_file_exists(){
    if [ ! -f "$1" ]
    then
        return 0;
    else
        return 1;
    fi
}

ensure_file_exists(){
    if [ ! -f "$1" ]
    then
        echo "File $1 does not seem to exist, aborting!"
        exit 255;
    fi
}

ensure_return_value(){
    if [ $? -ne $1 ]
    then
        exit 255
    fi
}

ensure_linking(){
    ensure_file_exists "$1"
    check_file_exists  "$2"
    if [ $? -eq 0 ]
    then
        echo "Creating a symbolic link between $1 $2"
        ln -s "$1" "$2"
        ensure_return_value 0
    else
        echo "$2 seems to exist, if its a copy, please ensure its upto date with $1"
    fi
}


# GIT Functions
check_git_dir(){
    out=$(git rev-parse --is-inside-work-tree 2>&1)

    if [ "$out" != "true" ]
    then
        echo "Not inside git directory!"
        exit 255;
    fi
}

# Project Specific functions
check_repo_is_alcp(){
    ensure_file_exists "$GIT_WORKING_DIR/CMakeLists.txt"
    cat $GIT_WORKING_DIR/CMakeLists.txt | grep -i "PROJECT" | grep -i "alcp" > /dev/null
    if [ $? -eq 0 ]
    then
        echo "Project ALCP Detected"
    else
        echo "Project is not ALCP, cannot continue!"
        exit 255;
    fi
}

ensure_clang_format(){
    ensure_linking "$GIT_WORKING_DIR/docs/clang-format.in" "$GIT_WORKING_DIR/.clang-format"
}

ensure_git_precommit_hook(){
    ensure_linking "$GIT_WORKING_DIR/scripts/git-hooks/pre-commit.sh" "$GIT_WORKING_DIR/.git/hooks/pre-commit"
}

ensure_git_hooks(){
    ensure_git_precommit_hook;
}

check_git_dir;

GIT_WORKING_DIR=$(git rev-parse --show-toplevel 2>&1)
echo "Found Working Git Directory as $GIT_WORKING_DIR"

check_repo_is_alcp;
ensure_clang_format;
ensure_git_hooks;