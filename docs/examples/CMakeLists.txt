
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
