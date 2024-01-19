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
 
# Inspired from Sphinx in CMake section of MSFT blog post
# https://devblogs.microsoft.com/cppblog/clear-functional-c-documentation-with-sphinx-breathe-doxygen-cmake/

set(DOXYGEN_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/doxygen)

find_package(Sphinx QUIET)
#message (STATUS "SPHINX_EXECUTABLE....${SPHINX_EXECUTABLE}")
#message (STATUS "Sphinx_FOUND....${Sphinx_FOUND}")

if (NOT Sphinx_FOUND OR NOT DOXYGEN_FOUND)
    message(FATAL "Sphinx/Doxygen not found. Skipping HTML generation..")
else()
    message(STATUS "Building Sphinx..")
    
    ## Configuration
    set(SPHINX_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/sphinx)
    file(MAKE_DIRECTORY ${SPHINX_BUILD_DIR}/html) #Sphinx won't create this for us
    set(SPHINX_HTML_INDEX ${SPHINX_BUILD_DIR}/html/indexpage.html)

    # Copy contents of below folders to Sphinx_Build Dir
    file(COPY ${PROJECT_SOURCE_DIR}/sphinx/ DESTINATION ${SPHINX_BUILD_DIR}/)

    # Function to create Symbolic Links for the dependent files
    FUNCTION(FILE_SYMLINK MYFILE OUTFILE)
        FILE(CREATE_LINK ${MYFILE} ${SPHINX_BUILD_DIR}/${OUTFILE} SYMBOLIC)
    ENDFUNCTION(FILE_SYMLINK MYFILE OUTFILE)

    FILE_SYMLINK(${PROJECT_SOURCE_DIR}/docs/resources/Quick_Start.md Quick_Start.md)
    FILE_SYMLINK(${PROJECT_SOURCE_DIR}/tests/README.md tests_README.md)
    FILE_SYMLINK(${PROJECT_SOURCE_DIR}/bench/README.md bench_README.md)
    FILE_SYMLINK(${PROJECT_SOURCE_DIR}/lib/compat/ipp/README.md ipp_README.md)
    FILE_SYMLINK(${PROJECT_SOURCE_DIR}/lib/compat/openssl/README.md openssl_README.md)

    # Only regenerate Sphinx when:
    # - Doxygen has rerun
    # - Our doc files have been updated
    # - The Sphinx config has been updated
    add_custom_command(OUTPUT ${SPHINX_HTML_INDEX}
                    COMMAND 
                    ${SPHINX_EXECUTABLE} -b html
                    # Tell Breathe where to find the Doxygen output
                    -Dbreathe_projects.aocl-crypto=${DOXYGEN_OUT_DIR}/xml
                    ${SPHINX_BUILD_DIR} ${SPHINX_BUILD_DIR}/html
                    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
                    DEPENDS ${SPHINX_BUILD_DIR}
                    COMMENT "Generating HTML with Sphinx")

    # Nice named target so we can run the job easily
    add_custom_target(SphinxDoc ALL DEPENDS ${SPHINX_HTML_INDEX})
endif()