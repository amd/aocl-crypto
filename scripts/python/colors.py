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

from config import *
class Colors:
    color_pool = {
        "RED":31,
        "GREEN":32,
        "YELLOW":33,
        "BLUE":34,
        "PURPLE":35,
        "CYAN":36,
        "LGRAY":37,
        "RESET":0
    }
    @staticmethod
    def reset():
        Colors.set_foreground("RESET")

    @staticmethod
    def set_foreground(color):
        if(color not in Colors.color_pool):
            if(VERBOSE_LEVEL>1):
                Colors.set_foreground("RED")
                print(f"Color : {color} not supported")
                Colors.reset()
        else:
            print(f"\033[;{Colors.color_pool[color]}m",end="\r")


if __name__=="__main__":
    for i in Colors.color_pool:
        Colors.set_foreground(i)
        print("Hello World")
        Colors.reset()
        print("Reset Successful")

    Colors.set_foreground("HELLO")
    print("Colors Tested Successfully")

    