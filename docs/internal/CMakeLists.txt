SET(ALCRYPTO_DOCS  ${CMAKE_CURRENT_SOURCE_DIR}/design.md)

STRING(REGEX REPLACE "\\.md(;|$)" ".pdf\\1" DOC_PDFS "${ALCRYPTO_DOCS}") 
STRING(REGEX REPLACE "\\.md(;|$)" "\\1" DOC_STEMS "${ALCRYPTO_DOCS}") 

IF( PDFLATEX AND PANDOC )
    #MESSAGE("${DOC_STEMS}")
    FOREACH(CDOC "${DOC_STEMS}")
        add_custom_command(
            OUTPUT ${CDOC}.pdf
            DEPENDS ${CDOC}.md
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
            -o ${CDOC}.pdf ${CDOC}.md
        )
        ADD_CUSTOM_TARGET(docs ALL DEPENDS ${CDOC}.pdf)
    ENDFOREACH()
ENDIF()

#ADD_CUSTOM_TARGET(docs ALL DEPENDS ${PDFDESIGN})
