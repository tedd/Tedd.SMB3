cmake_minimum_required(VERSION 3.24)
project(TeddSmbDirect LANGUAGES CXX)
if(NOT MSVC OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "The Network Direct provider requires MSVC for Windows x64.")
endif()

include(FetchContent)
FetchContent_Declare(networkdirect
  URL https://api.nuget.org/v3-flatcontainer/networkdirect/2.0.1/networkdirect.2.0.1.nupkg
  URL_HASH SHA256=3487c4f7c4cff89a5b3c515fcd77313f2771dbc2f54982c4060405906c95add5
  DOWNLOAD_NAME networkdirect.zip)
FetchContent_MakeAvailable(networkdirect)
add_library(Tedd.SMB3.NetworkDirect SHARED NetworkDirect.cpp)
target_compile_features(Tedd.SMB3.NetworkDirect PRIVATE cxx_std_17)
set_property(TARGET Tedd.SMB3.NetworkDirect PROPERTY MSVC_RUNTIME_LIBRARY MultiThreaded)
target_include_directories(Tedd.SMB3.NetworkDirect PRIVATE "${networkdirect_SOURCE_DIR}/include")
target_link_libraries(Tedd.SMB3.NetworkDirect PRIVATE "${networkdirect_SOURCE_DIR}/lib/x64/ndutil.lib" ws2_32 ole32 advapi32)

include(CTest)
if(BUILD_TESTING)
  add_executable(NetworkDirectCompletionTests ../../../tests/native/NetworkDirectCompletionTests.cpp)
  target_include_directories(NetworkDirectCompletionTests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}" "${networkdirect_SOURCE_DIR}/include")
  add_test(NAME NetworkDirectCompletions COMMAND NetworkDirectCompletionTests)
  set_tests_properties(NetworkDirectCompletions PROPERTIES TIMEOUT 10)
endif()
