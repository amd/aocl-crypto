#!/usr/bin/env python3
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


VERBOSE_LEVEL = 1

class Error:
    @staticmethod
    def print_error(frameinfo,error_str :str):
        print(f"Error {frameinfo.filename}:{frameinfo.lineno}\t{error_str}")

class Shell:
    import subprocess as sp
    @staticmethod
    def run_cmd_read(cmd):
        if(type(cmd) == str):
            cmd = cmd.split()
        process = Shell.sp.Popen(cmd,stdout=Shell.sp.PIPE,stderr=Shell.sp.PIPE,stdin=Shell.sp.PIPE)
        process.wait()
        stdout = process.stdout.read().decode()
        stderr = process.stderr.read().decode()
        return {"ret":process.returncode,"stdout":stdout,"stderr":stderr}

class Git:
    def __init__(self):
        self.reset()
    def enquire_unstaged_files(self):
        staged_files_cmd = "git diff --name-only"
        self.out = Shell.run_cmd_read(staged_files_cmd)
    def enquire_staged_files(self):
        staged_files_cmd = "git diff --name-only --cached"
        self.out = Shell.run_cmd_read(staged_files_cmd)
    def get_files_raw(self):
        assert(type(self.out) == dict)
        return self.out
    def get_files_list(self):
        assert(type(self.out) == dict)
        return self.out["stdout"].strip().splitlines()
    def get_status(self):
        assert(type(self.out) == dict)
        return self.out["ret"]
    def reset(self):
        self.out = None

class Copyright:
    from pathlib import Path
    from datetime import datetime
    from inspect import currentframe,getframeinfo

    def __init__(self,filename :str):
        self.file_p = self.Path(filename)
        self.file_s = filename

    @staticmethod
    def get_current_year():
        return str(Copyright.datetime.now().date().year)

    def find_first_commit_year(self):
        find_origin_log = "git log --reverse --format=%ad --date=format:%Y "+self.file_s
        out = Shell.run_cmd_read(find_origin_log)
        if(out["ret"]):
            if(VERBOSE_LEVEL>=0):
                frameinfo = Copyright.getframeinfo(Copyright.currentframe())
                Error.print_error(frameinfo,"git command execution failure, CMDLINE:"+find_origin_log)
            return None
        out = out["stdout"].strip().splitlines()
        if(len(out)>0):
            out = out[0]
        else:
            out = None
        return out

    def parse_source_file_start_end_year(self):
        file = open(self.file_s,"r")
        data = file.read()
        # Mangling the strings to Avoid detecting the below code as the fingerprint
        # While running precommit hook for this source file.
        index1 = data.find(", Advanced"+" "+"Micro Devices.")
        index2 = data.find("Copyright"+" "+"(C) ")
        if(index1 == -1 or index2 == -1):
            if(VERBOSE_LEVEL>=0):
                frameinfo = Copyright.getframeinfo(Copyright.currentframe())
                Error.print_error(frameinfo,"unable to find copyright fingerprint!")
            return None,None
        index2 = index2 + len("Copyright (C) ")
        assert(index1>index2)

        year = data[index2:index1]
        start_year = None
        end_year   = None
        if(year.find("-") != -1):
            # Type 1 FromYr-ToYr
            years = year.split("-")
            if(len(years) != 2):
                if(VERBOSE_LEVEL>=0):
                    frameinfo = Copyright.getframeinfo(Copyright.currentframe())
                    Error.print_error(frameinfo,"corrupted copyright year!")
                return None,None
            start_year,end_year = years
        else:
            # Type 2 CurrYr
            start_year = year
            end_year = year
        assert(int(start_year)<=int(end_year))

        return start_year,end_year

    def parse_file_start_end_year(self):
        file = self.file_p
        ext = file.suffix
        start_year,end_year = None,None
        # Format type 1, source code.
        if(ext == ".cc" or ext == ".c" or ext == ".inc" or ext == ".hh" or ext == ".h"):
            start_year, end_year = self.parse_source_file_start_end_year()
        # Format type 2, scripts
        elif(ext == ".py" or ext == ".cmake" or ext == ".sh"):
            start_year, end_year = self.parse_source_file_start_end_year() # Seems somehow we made a good generic parser accidentally
        elif((file.stem + ext) == "CMakeLists.txt"):
            start_year, end_year = self.parse_source_file_start_end_year() # Seems somehow we made a good generic parser accidentally
        else:
            if(VERBOSE_LEVEL>=0):
                frameinfo = Copyright.getframeinfo(Copyright.currentframe())
                Error.print_error(frameinfo,"Unknown File Extention")
            return None
        return start_year,end_year
        # TODO: Exclude cmake from the above.

    def ensure_copyright_years(self):
        exp_start_year = self.find_first_commit_year()
        exp_end_year = self.get_current_year()
        if(not exp_start_year):
            # Sometimes the file might be a new file
            exp_start_year = exp_end_year

        assert(type(exp_start_year)==str)
        assert(type(exp_end_year)==str)
        assert(int(exp_start_year)<=int(exp_end_year))

        # Act -> Actual
        act = self.parse_file_start_end_year()
        assert(sum([(type(i) == str) for i in act])==2)
        if((exp_start_year,exp_end_year) == act):
            if(VERBOSE_LEVEL>=2):
                print("PASS")
            return True
        else:
            act_start_year,act_end_year = act
            if(VERBOSE_LEVEL>=1):
                if(exp_start_year == act_start_year):
                    if(VERBOSE_LEVEL>=2):
                        print("Start year is correct")
                else:
                    print(f"Expected start was {exp_start_year} but got {act_start_year}")
                if(exp_end_year == act_end_year):
                    if(VERBOSE_LEVEL>=2):
                        print("End year is correct")
                else:
                    print(f"Expected end was {exp_end_year} but got {act_end_year}")
            if(VERBOSE_LEVEL>=1):
                print("FAIL")
            return False

def ensure_staged_files_copyrights():
    git = Git()
    git.enquire_staged_files()
    files = git.get_files_list()
    del git
    problems_detected = False
    for i in files:
        if VERBOSE_LEVEL>1:
            print("Checking file:",i)
        copyright = Copyright(i)
        try:
            if(not copyright.ensure_copyright_years()):
                problems_detected = True
                if(VERBOSE_LEVEL>=1):
                    print("Above reported problem is for file:"+i+"\n")
        except AssertionError as e:
            print(e)
            print("Problem detected while parsing for Copyright for file:"+i)
            # raise e
            problems_detected = True
        del copyright
    if(problems_detected):
        exit(-1)

ensure_staged_files_copyrights()