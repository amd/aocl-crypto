# Index/Main files to read from
SET(ALCP_USAGE_DOC  openssl.md ipp.md)

# Combine one or more Index/Main doc files into an array for
# generating each pdf
SET(ALCRYPTO_DOCS  ${ALCP_USAGE_DOC}
  ${ALCP_TESTING_DOC}
)

# Replace .md with .pdf in all entry of ALCRYPTO_DOCS array
STRING(REGEX REPLACE "\\.md(;|$)" ".pdf\\1" DOC_PDFS "${ALCRYPTO_DOCS}")
# Remove .md and assuming a directory like that will
# exist for each entry in ALCRYPTO_DOCS array
STRING(REGEX REPLACE "\\.md(;|$)" "\\1" DOC_STEMS "${ALCRYPTO_DOCS}") 

IF( PDFLATEX AND PANDOC )
    # For each "Index/Main" file named directory, include all .md
    # files in them.
    FOREACH(CDOC ${DOC_STEMS})
      FILE(GLOB DOC_FILES ${CDOC}/*.md)
      MESSAGE("Including Documents: ${DOC_FILES}")
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
            # Klavika font needs to be downloaded
            # -V mainfont="Klavika"
            # -V mainfont="sans"
            -V documentclass=report
            -V fontsize=12pt
            -V papersize=B4
            -V geometry:margin=1in
            -o ${CDOC}.pdf ${CDOC}.md ${DOC_FILES}
      )
      MESSAGE(STATUS "DOC OUTPUT FILE ${CDOC}.pdf")
    ENDFOREACH()
    # Create a target named docs and add "Index/Main" file name 
    # with pdf extension as a dependancy
    ADD_CUSTOM_TARGET(docs_compat ALL DEPENDS ${DOC_PDFS})
ENDIF()

#ADD_CUSTOM_TARGET(docs ALL DEPENDS ${PDFDESIGN})
