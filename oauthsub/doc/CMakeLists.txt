set(oauthsub_docs conf.py changelog.rst index.rst todo.rst README.rst)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/oauthsub_doc.stamp
                   COMMAND sphinx-build -M html ${CMAKE_CURRENT_SOURCE_DIR}
                           ${CMAKE_CURRENT_BINARY_DIR}
                   COMMAND touch ${CMAKE_CURRENT_BINARY_DIR}/oauthsub_doc.stamp
                   DEPENDS ${oauthsub_docs}
                   WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
add_custom_target(oauthsub_doc
                  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/oauthsub_doc.stamp)
add_dependencies(doc oauthsub_doc)
