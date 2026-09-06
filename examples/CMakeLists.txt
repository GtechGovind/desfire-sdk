add_executable(desfire_c_offline_example c/offline_key_derivation.c)
set_target_properties(desfire_c_offline_example PROPERTIES
    C_STANDARD 99
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS NO)
target_link_libraries(desfire_c_offline_example PRIVATE desfire::c)

if(DESFIRE_BUILD_CPP17)
    add_executable(desfire_cpp17_offline_example cpp17/offline_key_derivation.cpp)
    set_target_properties(desfire_cpp17_offline_example PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS NO)
    target_link_libraries(desfire_cpp17_offline_example PRIVATE desfire::cpp17)
endif()
