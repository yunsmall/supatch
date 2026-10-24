cmake_minimum_required(VERSION 3.13)
project("kpatch")

include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../include)

if(ANDROID)
set(OPT_FLAGS "-ffunction-sections -fdata-sections -fvisibility=hidden -fvisibility-inlines-hidden -mllvm -polly -O3 -flto")
else()
set(OPT_FLAGS "-O3")
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_GNU_SOURCE -std=c++11 ${OPT_FLAGS}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE -std=c11 ${OPT_FLAGS}")

if(ANDROID)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DANDROID")    
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DANDROID")    
endif()

set(SRCS
    kpatch.c
    kpm.c
    kpextension.c
    rehook.c
    supatch.c
)

add_library(kp STATIC ${SRCS})
add_executable(kpatch ${SRCS} main.c)

# 静态库没有链接步骤，target_link_options 只对可执行文件设置
target_link_options(kpatch PRIVATE "-Wl,--build-id=none" "-Wl,-icf=safe,--lto-O3" "-Wl,-s,-x,--gc-sections" "-Wl,--no-undefined")
