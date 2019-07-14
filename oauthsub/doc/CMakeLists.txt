if(CMAKE_GENERATOR STREQUAL "Unix Makefiles")
  add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/rst_manifest.txt
    COMMAND python -B ${CMAKE_SOURCE_DIR}/doc/find_rst.py
            --manifest-path ${CMAKE_CURRENT_BINARY_DIR}/rst_manifest.txt
            --touch ${CMAKE_SOURCE_DIR}/oauthsub
    DEPENDS ${CMAKE_SOURCE_DIR}/doc/find_rst.py
    COMMENT "Scanning RST for oauthsub")
endif()

add_custom_target(
  scanrst-oauthsub_docs
  COMMAND python -B ${CMAKE_SOURCE_DIR}/doc/find_rst.py
          --manifest-path ${CMAKE_CURRENT_BINARY_DIR}/rst_manifest.txt
          --touch ${CMAKE_SOURCE_DIR}/oauthsub
  DEPENDS ${CMAKE_SOURCE_DIR}/doc/find_rst.py
  BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/rst_manifest.txt
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  COMMENT "Scanning RST for oauthsub")

add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/oauthsub_doc.stamp
  COMMAND env PYTHONPATH=${CMAKE_SOURCE_DIR} sphinx-build -M
          html ${CMAKE_CURRENT_SOURCE_DIR}
          ${CMAKE_CURRENT_BINARY_DIR}
  COMMAND touch
          ${CMAKE_CURRENT_BINARY_DIR}/oauthsub_doc.stamp
  DEPENDS conf.py
          ${CMAKE_CURRENT_BINARY_DIR}/rst_manifest.txt
          ${CMAKE_SOURCE_DIR}/doc/conf.py
          ${CMAKE_SOURCE_DIR}/doc/sphinx-static/css/cheshire_theme.css
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

add_custom_target(
  oauthsub_doc
  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/oauthsub_doc.stamp)

add_dependencies(doc oauthsub_doc)
