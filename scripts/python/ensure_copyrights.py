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

from error import Error
from git import Git
from config import VERBOSE_LEVEL
from colors import Colors
import sys
from inspect import currentframe,getframeinfo
class Copyright:
    from pathlib import Path
    from datetime import datetime
    from inspect import currentframe,getframeinfo

    def __init__(self,filename :str):
        self.file_p = self.Path(filename)
        self.file_s = filename
        self.extensions_supported = [".cc",".c",".inc",".hh",".h",".py",".cmake",".sh"]
        if(not ((self.file_p.suffix in self.extensions_supported) or (self.file_p.stem + self.file_p.suffix).endswith("CMakeLists.txt"))):
            if(VERBOSE_LEVEL>1):
                frameinfo = Copyright.getframeinfo(Copyright.currentframe())
                Error.print_error(frameinfo,"File extension not supported!")
            raise(NotImplementedError(f"Extension {self.file_p.suffix} is not supported"))

    @staticmethod
    def get_current_year():
        return str(Copyright.datetime.now().date().year)

    def find_first_commit_year(self):
        git = Git()
        if not git.enquire_first_commit_year(file_s=self.file_s):
            return 0
        out = git.get_str()
        return out

    def find_last_commit_year(self):
        git = Git()
        if not git.enquire_last_commit_year(file_s=self.file_s):
            return 0
        out = git.get_str()
        return out

    def parse_source_file_start_end_year(self):
        file = open(self.file_s,"r")
        data = file.read(100)
        # Mangling the strings to Avoid detecting the below code as the fingerprint
        # While running precommit hook for this source file.
        index1 = data.find(", Advanced"+" "+"Micro Devices.")
        index2 = data.find("Copyright"+" "+"(C) ")
        if(index1 == -1 or index2 == -1):
            if(VERBOSE_LEVEL>=1):
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
        start_year, end_year = self.parse_source_file_start_end_year()
        return start_year,end_year
        # TODO: Exclude cmake from the above.

    def ensure_copyright_years(self,end_year_is_current=True):
        exp_start_year = self.find_first_commit_year()
        exp_end_year = None
        if(end_year_is_current):
            exp_end_year = self.get_current_year()
        else:
            exp_end_year = self.find_last_commit_year()
        if(not exp_start_year):
            # Sometimes the file might be a new file
            exp_start_year = exp_end_year

        assert(type(exp_start_year)==str)
        assert(type(exp_end_year)==str)
        assert(int(exp_start_year)<=int(exp_end_year))

        # Act -> Actual
        act = self.parse_file_start_end_year()
        if(sum([(type(i) == str) for i in act])!=2):
            if(VERBOSE_LEVEL>=1):
                frameinfo = Copyright.getframeinfo(Copyright.currentframe())
                Error.print_error(frameinfo,"FAIL")
            return False
        if((exp_start_year,exp_end_year) == act):
            if(VERBOSE_LEVEL>=2):
                frameinfo = Copyright.getframeinfo(Copyright.currentframe())
                Error.print_ok(frameinfo,"PASS")
            return True
        else:
            act_start_year,act_end_year = act
            if(VERBOSE_LEVEL>=1):
                if(exp_start_year == act_start_year):
                    if(VERBOSE_LEVEL>=2):
                        Colors.set_foreground("BLUE")
                        print("Start year is correct")
                        Colors.reset()
                else:
                    Colors.set_foreground("RED")
                    print(f"Expected start was {exp_start_year} but got {act_start_year}")
                    Colors.reset()
                if(exp_end_year == act_end_year):
                    if(VERBOSE_LEVEL>=2):
                        Colors.set_foreground("BLUE")
                        print("End year is correct")
                        Colors.reset()
                else:
                    Colors.set_foreground("RED")
                    print(f"Expected end was {exp_end_year} but got {act_end_year}")
                    Colors.reset()
            if(VERBOSE_LEVEL>=1):
                frameinfo = Copyright.getframeinfo(Copyright.currentframe())
                Error.print_error(frameinfo,"FAIL")
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
            if(not copyright.ensure_copyright_years(end_year_is_current=True)):
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

def get_all_files():
    g = Git()
    g.enquire_all_files()
    return g.get_files_list()

def copyright_check_all():
    files = get_all_files()
    if(not files):
        frameinfo = getframeinfo(currentframe())
        Error.print_error(frameinfo,"No files found")
        return
    for i in files:
        if(VERBOSE_LEVEL>=1):
            frameinfo = getframeinfo(currentframe())
            Error.print_info(frameinfo,i)
        try:
            copyright = Copyright(i)
            copyright.ensure_copyright_years(end_year_is_current=False)
            del copyright
        except NotImplementedError as e:
            if(VERBOSE_LEVEL>1):
                frameinfo = getframeinfo(currentframe())
                Error.print_warn(frameinfo,"Skipping, Invalid File Extension")
            continue
        if(VERBOSE_LEVEL>=1):
            print()

def copyright_check_file(file):
    if(VERBOSE_LEVEL>=1):
        frameinfo = getframeinfo(currentframe())
        Error.print_info(frameinfo,file)
    try:
        copyright = Copyright(file)
        copyright.ensure_copyright_years(end_year_is_current=False)
        del copyright
    except NotImplementedError as e:
        print("Skipping, Invalid File Extension")
        return False
    return True


def help():
    py_file = sys.argv[0]
    for i in arguments:
        print(i,arguments[i][2])

arguments = {
    "--help":[help,False," for help."],
    "--all" :[copyright_check_all,False," check all files tracked by git recursively for copyright."],
    "--file":[copyright_check_file,True," check the given file for copyright issues."]
}

def argument_parser():
    if(len(sys.argv) == 1):
        return
    i = 1
    while(i<len(sys.argv)):
        curr = sys.argv[i].lower()
        if(curr in arguments):
            exec = arguments[curr][0]
            if(arguments[curr][1]):
                i+=1
                if(i<len(sys.argv)):
                    next_arg = sys.argv[i]
                    exec(next_arg)
                else:
                    frameinfo = getframeinfo(currentframe())
                    Error.print_error(frameinfo,"Was expecting a value for the argument!")
                    exit(-1)
            else:
                exec()
        else:
            frameinfo = getframeinfo(currentframe())
            Error.print_error(frameinfo,"Argument not understood "+curr)
            exit(-1)
        i+=1
    exit(0)


argument_parser()

try:
    ensure_staged_files_copyrights()
except Exception as e:
    if(VERBOSE_LEVEL>1):
        print("Raising captured exception")
        raise e
    else:
        print("Execption occured, terminating")
    exit(-1)

