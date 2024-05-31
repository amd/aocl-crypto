#!/usr/bin/env python3
# Copyright (C) 2024, Advanced Micro Devices. All rights reserved.
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

import os
import sys
import ntpath
from subprocess import CalledProcessError, check_output

def Error_Exit(msg):
    print("Error message:" + msg)
    exit(-1)

def RunCommand(args_list):
    if args_list is None or []:
        Error_Exit("Empty arguments provided!")
    args_str = ""
    output = {}
    # concat list
    args_str = ' '.join(args_list)
    print("Running cmd: " + args_str)
    try:
        output['output_str'] = check_output(
            args_str, shell=True).decode('utf-8')
    except CalledProcessError as e:
        output['err_str'] = e.output.decode('utf-8')
        output['err_code'] = e.returncode
    return output

# build dir should be an argument to this script
if len(sys.argv) < 2:   Error_Exit("Run the script with build directory as an argument!")
build_dir = sys.argv[1]
Fuzz_Build_Dir = os.path.join(build_dir, 'tests', 'Fuzz')

ScriptPath = os.path.dirname(os.path.abspath(__file__))

CorpusDir = os.path.abspath(os.path.join(ScriptPath, 'Corpus'))
if not os.path.isdir(CorpusDir):
    Error_Exit("Crash corpus directory not found!")

# FIXME: accept this module as a param?
Fuzz_Targets = ['Cipher','Digest', 'Ec', 'Mac', 'rng', 'Rsa',]

Fuzz_Executables = []
fuzz_dir = None

# now find all executables
for FuzzTarget in Fuzz_Targets:
    fuzz_dir = os.path.abspath(os.path.join(Fuzz_Build_Dir, FuzzTarget))
    for f in os.listdir(fuzz_dir):
        if 'test_fuzz' in f:
            Fuzz_Executables.append(os.path.join(fuzz_dir, f))
            
# run exes
default_args = ['-rss_limit_mb=32768', '-detect_leaks=0', '-max_total_time=20',]
crash_path_arg = '-exact_artifact_path='
for Exe in Fuzz_Executables:
    crash_path = os.path.join(CorpusDir, ntpath.basename(Exe))
    RunCommand([Exe] + default_args + [crash_path_arg + crash_path])

print ("\nRan fuzz test targets, please check the directory " + CorpusDir + " for crash dump files")
print ("\nTo reproduce the errors, re-run the executables with the crash dump file as an argument. Cheers!")
    
     
    