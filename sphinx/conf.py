# Copyright (C) 2024, Advanced Micro Devices, Inc. All rights reserved.
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
###############################################################################

# Configuration file for the Sphinx documentation builder.

# Project information 
project = 'AOCL-Cryptography'
copyright = '@COPYRIGHT_YEAR@, Advanced Micro Devices, Inc'
author = 'Advanced Micro Devices, Inc'
version = 'Version @AOCL_RELEASE_VERSION@'

# Options for HTML output 
html_title = 'Home'
html_theme = 'rocm_docs_theme'
html_theme_options = {
    "link_main_doc": False,
    "flavor": "local",
    "repository_provider" : None,
}

# The suffix(es) of source filenames.
# You can specify multiple suffix as a list of string:
source_suffix = ['.rst', '.md']

# The master toctree document.
master_doc = 'index'

# Add any Sphinx extension module names here, as strings.
# They can be extensions coming with Sphinx (named 'sphinx.ext.*') or
# your custom ones.
extensions = ['breathe', 'myst_parser', 'sphinx.ext.mathjax']
myst_enable_extensions = ["html_admonition", 
                        "linkify", 
                        "attrs_inline"
                        ]
breathe_projects = { "aocl-crypto": "build/doxygen/xml" }
breathe_default_project = "aocl-crypto"

myst_title_to_header = True
myst_heading_anchors = 3
suppress_warnings = ["myst.header", "myst.xref_missing"]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['templates']

# If true, `todo` and `todoList` produce output, else they produce nothing.
todo_include_todos = False
