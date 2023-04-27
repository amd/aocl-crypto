 # Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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
 

SET(ALCP_DESIGN_DOC  ${CMAKE_CURRENT_SOURCE_DIR}/design.md)


SET(ALCRYPTO_DOCS  ${ALCP_DESIGN_DOC}
  ${ALCP_TESTING_DOC}
  )

STRING(REGEX REPLACE "\\.md(;|$)" ".pdf\\1" DOC_PDFS "${ALCRYPTO_DOCS}") 
STRING(REGEX REPLACE "\\.md(;|$)" "\\1" DOC_STEMS "${ALCRYPTO_DOCS}") 

IF( PDFLATEX AND PANDOC )
    MESSAGE("${DOC_STEMS}")
    FOREACH(CDOC "${DOC_STEMS}")
      FILE(GLOB DOC_FILES ${CDOC}/*.md)
      MESSAGE("ayyayyo ${DOC_FILES}")
      ADD_CUSTOM_COMMAND(
            OUTPUT ${CDOC}.pdf
            DEPENDS ${CDOC}.md ${THIS_DOC}
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            COMMAND pandoc
            --table-of-contents
            --pdf-engine=xelatex
            --from=markdown
            --number-sections
            --top-level-division=part
            --indented-code-classes=c++
            --highlight-style=zenburn
            -V mainfont="Klavika"
            -V documentclass=report
            -V fontsize=12pt
            -V papersize=B4
            -V geometry:margin=1in
            -o ${CDOC}.pdf ${CDOC}.md ${DOC_FILES}
        )
        ADD_CUSTOM_TARGET(docs ALL DEPENDS ${CDOC}.pdf)
    ENDFOREACH()
ENDIF()

#ADD_CUSTOM_TARGET(docs ALL DEPENDS ${PDFDESIGN})
