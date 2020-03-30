cmake_minimum_required(VERSION 3.6)           #普通版本的clang

# configure import libs
set(distribution_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../distribution)

add_library(lib_tongxin SHARED IMPORTED)
set_target_properties(lib_tongxin PROPERTIES IMPORTED_LOCATION
    ${distribution_DIR}/tongxin/lib/${ANDROID_ABI}/libskf.so)

add_library( # Sets the name of the library.
             SDKey
             # Sets the library as a shared library.
             SHARED
             # Provides a relative path to your source file(s).
             src/main/jni/JNIEncrypt.c
             src/main/jni/base64.h
             src/main/jni/base64.c
             src/main/jni/APDUs.h
             src/main/jni/APDUs.c
             )

# 搜索指定的预构建库并将路径存储为变量。 因为默认情况下，CMake在搜索路径中包含系统库，
# 所以您只需要指定公共NDK库的名称你想添加。 在完成构建之前，CMake验证库存在。

find_library( # Sets the name of the path variable.
              log-lib
              # Specifies the name of the NDK library that
              # you want CMake to locate.
              log )

# 指定CMake应链接到目标库的库。 您可以链接多个库，例如在此构建脚本中定义的库，预构建的第三方库或系统库。

target_include_directories(SDKey PRIVATE source ${distribution_DIR}/tongxin/include)

target_link_libraries( # Specifies the target library.
                       SDKey
                       lib_tongxin
                       # included in the NDK.
                       ${log-lib} )
