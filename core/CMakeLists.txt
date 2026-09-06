# Keep the installed surface to one modern core target. The object targets below are
# build-only partitions: they shorten incremental rebuilds and make source ownership
# explicit without creating protocol-domain libraries for consumers to couple to.
add_library(ev3_core_build_interface INTERFACE)
target_include_directories(ev3_core_build_interface INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_link_libraries(ev3_core_build_interface INTERFACE foundation)

# Add one private protocol-domain partition with the core's build-only include path
# and foundation dependency. Domain-to-domain calls are resolved only when ev3_core
# composes every object below, so no private target enters the install export.
function(desfire_add_ev3_object_domain target)
    desfire_add_object_library(${target} ${ARGN})
    target_link_libraries(${target} PRIVATE ev3_core_build_interface)
endfunction()

desfire_add_ev3_object_domain(ev3_core_model_objects
    src/model/version.cpp)

desfire_add_ev3_object_domain(ev3_core_native_raw_objects
    src/native/raw/codec.cpp
    src/native/raw/channel.cpp)

desfire_add_ev3_object_domain(ev3_core_native_checked_objects
    src/native/checked/command.cpp
    src/native/checked/applications.cpp
    src/native/checked/card_management.cpp
    src/native/checked/files.cpp
    src/native/checked/keys.cpp
    src/native/checked/transactions.cpp)

desfire_add_ev3_object_domain(ev3_core_key_derivation_objects
    src/security/key_derivation/aes128.cpp
    src/security/key_derivation/nxp_aes128.cpp)

desfire_add_ev3_object_domain(ev3_core_standard_aes_objects
    src/security/standard_aes/authentication.cpp
    src/security/standard_aes/session.cpp)

desfire_add_ev3_object_domain(ev3_core_ev2_objects
    src/security/ev2/authentication.cpp
    src/security/ev2/session.cpp)

desfire_add_ev3_object_domain(ev3_core_native_secure_objects
    src/native/secure/channel.cpp)

desfire_add_ev3_object_domain(ev3_core_iso7816_raw_objects
    src/iso7816/raw/codec.cpp
    src/iso7816/raw/channel.cpp)

desfire_add_ev3_object_domain(ev3_core_iso7816_checked_objects
    src/iso7816/checked/command.cpp
    src/iso7816/checked/channel.cpp)

desfire_add_ev3_object_domain(ev3_core_iso7816_aes_objects
    src/iso7816/security/aes/authentication.cpp
    src/iso7816/security/aes/session.cpp)

desfire_add_ev3_object_domain(ev3_core_offline_objects
    src/offline/delegated_application.cpp
    src/offline/mifare_classic_license.cpp
    src/offline/originality_signature.cpp
    src/offline/transaction_mac.cpp)

desfire_add_ev3_object_domain(ev3_core_managed_objects
    src/managed/card_lifecycle.cpp
    src/managed/card_discovery.cpp
    src/managed/card_authentication.cpp
    src/managed/card_applications.cpp
    src/managed/card_management.cpp
    src/managed/card_keys.cpp
    src/managed/card_files.cpp
    src/managed/card_transactions.cpp
    src/managed/card_iso7816.cpp)

set(ev3_core_object_targets
    ev3_core_model_objects
    ev3_core_native_raw_objects
    ev3_core_native_checked_objects
    ev3_core_key_derivation_objects
    ev3_core_standard_aes_objects
    ev3_core_ev2_objects
    ev3_core_native_secure_objects
    ev3_core_iso7816_raw_objects
    ev3_core_iso7816_checked_objects
    ev3_core_iso7816_aes_objects
    ev3_core_offline_objects
    ev3_core_managed_objects)

# libFuzzer must instrument the object partitions themselves; applying this option only to the
# source-free aggregate archive would leave the protocol implementation uninstrumented.
if(DESFIRE_BUILD_FUZZERS)
    foreach(object_target IN LISTS ev3_core_object_targets)
        target_compile_options(${object_target} PRIVATE
            $<$<CXX_COMPILER_ID:AppleClang,Clang>:-fsanitize=fuzzer-no-link>)
    endforeach()
endif()

set(ev3_core_objects "")
foreach(object_target IN LISTS ev3_core_object_targets)
    list(APPEND ev3_core_objects $<TARGET_OBJECTS:${object_target}>)
endforeach()

# A static core gives the C ABI one PIC-safe implementation to embed and avoids
# promising an unstable C++ dynamic ABI. desfire::ev3_core is the only public target.
desfire_add_library(ev3_core STATIC ${ev3_core_objects})
add_library(desfire::ev3_core ALIAS ev3_core)

target_include_directories(ev3_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)
target_link_libraries(ev3_core PUBLIC foundation)

install(DIRECTORY include/ DESTINATION include)
