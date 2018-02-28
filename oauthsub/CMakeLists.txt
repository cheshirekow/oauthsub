set(oauthsub_py_files __init__.py __main__.py auth_service.py)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/oauthsub_format.stamp
                   COMMAND autopep8 -i ${oauthsub_py_files}
                   COMMAND cmake-format -i CMakeLists.txt doc/CMakeLists.txt
                   COMMAND touch
                           ${CMAKE_CURRENT_BINARY_DIR}/oauthsub_format.stamp
                   DEPENDS ${oauthsub_py_files}
                   WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
add_custom_target(oauthsub_format
                  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/oauthsub_format.stamp)
add_dependencies(format oauthsub_format)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/oauthsub_lint.stamp
                   COMMAND pylint ${oauthsub_py_files}
                   COMMAND touch ${CMAKE_CURRENT_BINARY_DIR}/oauthsub_lint.stamp
                   DEPENDS ${oauthsub_py_files}
                   WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
add_custom_target(oauthsub_lint
                  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/oauthsub_lint.stamp)

# NOTE(josh): format before lint-check, avoid formatting lint
add_dependencies(oauthsub_lint oauthsub_format)
add_dependencies(lint oauthsub_lint)

add_subdirectory(doc)
