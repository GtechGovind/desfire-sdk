include_guard(GLOBAL)

find_package(Python3 COMPONENTS Interpreter QUIET)
find_package(Doxygen QUIET)

if(Python3_Interpreter_FOUND)
    add_custom_target(docs-check
        COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/check-cpp-documentation.py
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        COMMENT "Checking C and C++ documentation coverage"
        VERBATIM)
    add_custom_target(api-check
        COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/check-api-coverage.py
                --check
        COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/generate-bindings.py
                --check
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        COMMENT "Checking canonical EV3 API and generated binding coverage"
        VERBATIM)
    if(TARGET desfire_c)
        add_custom_target(abi-check
            COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/check-abi.py
                    --library $<TARGET_FILE:desfire_c>
            DEPENDS desfire_c
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
            COMMENT "Checking C ABI symbol baseline and linked export surface"
            VERBATIM)
    endif()
    add_custom_target(coverage-check
        COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/check-coverage.py
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        COMMENT "Checking EV3 command coverage evidence"
        VERBATIM)
    add_custom_target(format-check
        COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/check-format.py
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        COMMENT "Checking C and C++ formatting"
        VERBATIM)
endif()

if(DOXYGEN_FOUND)
    set(DESFIRE_DOXYGEN_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/documentation")
    configure_file(${PROJECT_SOURCE_DIR}/docs/Doxyfile.in
                   ${PROJECT_BINARY_DIR}/Doxyfile @ONLY)
    add_custom_target(docs
        COMMAND ${DOXYGEN_EXECUTABLE} ${PROJECT_BINARY_DIR}/Doxyfile
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        COMMENT "Generating DESFire EV3 API documentation"
        VERBATIM)
else()
    add_custom_target(docs
        COMMAND ${CMAKE_COMMAND} -E echo
                "Doxygen is unavailable; install it to generate API documentation"
        COMMAND ${CMAKE_COMMAND} -E false
        VERBATIM)
endif()
