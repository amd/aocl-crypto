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
        set_fg_color $RED
        echo "File $1 does not seem to exist, aborting!"
        reset_color
        exit 255;
    fi
}

ensure_return_value(){
    if [ $? -ne $1 ]
    then
        exit 255
    fi
}

warn_return_value(){
    if [ $? -ne $1 ]
    then
        set_fg_color $RED
        echo "Above operation might have FAILED!"
        reset_color
    fi
}

ensure_linking(){
    ensure_file_exists "$1"
    check_file_exists  "$2"
    if [ $? -eq 0 ]
    then
        set_fg_color $GREEN
        echo "Creating a symbolic link between $1 $2"
        ln -s "$1" "$2"
        reset_color
        ensure_return_value 0
    else
        set_fg_color $YELLOW
        echo "$2 seems to exist, if its a copy, please ensure its upto date with $1"
        reset_color
    fi
}


# GIT Functions
check_git_dir(){
    out=$(git rev-parse --is-inside-work-tree 2>&1)

    if [ "$out" != "true" ]
    then
        set_fg_color $RED
        echo "Not inside git directory!"
        reset_color
        exit 255;
    fi
}

# Project Specific functions
check_repo_is_alcp(){
    ensure_file_exists "$GIT_WORKING_DIR/CMakeLists.txt"
    cat $GIT_WORKING_DIR/CMakeLists.txt | grep -i "PROJECT" | grep -i "alcp" > /dev/null
    if [ $? -eq 0 ]
    then
        set_fg_color $GREEN
        echo "Project ALCP Detected"
        reset_color
    else
        set_fg_color $RED
        echo "Project is not ALCP, cannot continue!"
        reset_color
        exit 255;
    fi
}

ensure_clang_format(){
    ensure_linking "$GIT_WORKING_DIR/docs/clang-format.in" "$GIT_WORKING_DIR/.clang-format"
}

ensure_git_precommit_hook(){
    ensure_linking "$GIT_WORKING_DIR/scripts/git-hooks/pre-commit.sh" "$GIT_HOOKS_DIR/pre-commit"
}

ensure_git_hooks(){
    ensure_git_precommit_hook;
}

clean(){
    # TODO: Needs argument parser
    if [ "$1" = "-c" ]
    then
        set_fg_color $YELLOW
        echo "Removing ""$GIT_WORKING_DIR/.git/hooks/pre-commit"
        reset_color
        rm "$GIT_HOOKS_DIR/pre-commit" 2>&1 > /dev/null
        warn_return_value 0
        set_fg_color $YELLOW
        echo "Removing ""$GIT_WORKING_DIR/.clang-format"
        reset_color
        rm "$GIT_WORKING_DIR/.clang-format" 2>&1 > /dev/null
        warn_return_value 0

        set_fg_color $GREEN
        echo "Done cleaning"
        reset_color
        exit 0
    fi
}

check_git_dir;

GIT_WORKING_DIR=$(git rev-parse --show-toplevel 2>&1)
GIT_HOOKS_DIR=$(git rev-parse --git-path hooks 2>&1)

# Include the capability for colors
source $GIT_WORKING_DIR/scripts/colors.sh

set_fg_color $YELLOW
echo "Found Working Git Directory as $GIT_WORKING_DIR"
echo "Found Working Git Hooks Directory as $GIT_HOOKS_DIR"
reset_color

clean $@;
check_repo_is_alcp;
ensure_clang_format;
ensure_git_hooks;