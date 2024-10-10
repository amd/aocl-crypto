#!/usr/bin/env python3
# Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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

from config import VERBOSE_LEVEL
from shell import Shell
from error import Error
class Git:
    from inspect import currentframe,getframeinfo
    def __init__(self):
        self.reset()
    def enquire_unstaged_files(self):
        staged_files_cmd = "git diff --name-only"
        self.out = Shell.run_cmd_read(staged_files_cmd)
    def enquire_staged_files(self):
        staged_files_cmd = "git diff --name-only --cached"
        self.out = Shell.run_cmd_read(staged_files_cmd)
    # TODO: Revisit this below function.
    def enquire_first_commit_year(self,file_s):
        find_origin_log = "git log --reverse --format=%ad --date=format:%Y "+file_s
        out = Shell.run_cmd_read(find_origin_log)
        if(out["ret"]):
            if(VERBOSE_LEVEL>=0):
                frameinfo = Git.getframeinfo(Git.currentframe())
                Error.print_error(frameinfo,"git command execution failure, CMDLINE:"+find_origin_log)
            return None
        out = out["stdout"].strip().splitlines()
        if(len(out)>0):
            self.out = out[0]
            return True
        else:
            self.out = None
            return False
    def enquire_last_commit_year(self,file_s):
        find_origin_log = "git log --format=%ad --date=format:%Y "+file_s
        out = Shell.run_cmd_read(find_origin_log)
        if(out["ret"]):
            if(VERBOSE_LEVEL>=0):
                frameinfo = Git.getframeinfo(Git.currentframe())
                Error.print_error(frameinfo,"git command execution failure, CMDLINE:"+find_origin_log)
            return None
        out = out["stdout"].strip().splitlines()
        if(len(out)>0):
            self.out = out[0]
            return True
        else:
            self.out = None
            return False
    def enquire_all_files(self):
        command = "git ls-tree -r HEAD --name-only"
        self.out = Shell.run_cmd_read(command)
        return True
    def exec(self,cmd):
        if(type(cmd) == str):
            command = "git "+cmd
        elif(type(cmd) == list):
            command = ["git"]+cmd
        else:
            return False
        self.out = Shell.run_cmd_read(command)
        return True
    def get_files_raw(self):
        assert(type(self.out) == dict)
        return self.out
    def get_files_list(self):
        assert(type(self.out) == dict)
        return self.out["stdout"].strip().splitlines()
    def get_status(self):
        assert(type(self.out) == dict)
        return self.out["ret"]
    def get_int(self):
        assert(type(self.out) == int)
        return self.out
    def get_str(self):
        assert(type(self.out) == str)
        return self.out
    def reset(self):
        self.out = None