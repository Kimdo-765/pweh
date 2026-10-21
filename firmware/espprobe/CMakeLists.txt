# probe-hello 전용 빌드. 타깃 버스 기능은 이 프로젝트에 연결하지 않는다.
cmake_minimum_required(VERSION 3.24)
set(IDF_TARGET esp32s3 CACHE STRING "고정 계측기 타깃")
file(STRINGS "${CMAKE_CURRENT_LIST_DIR}/VERSION" PROJECT_VER LIMIT_COUNT 1)
set(COMPONENTS main)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(pweh_espprobe)
idf_build_set_property(COMPILE_DEFINITIONS CFG_TUD_CDC_TX_OVERWRITABLE_IF_NOT_CONNECTED=0 APPEND)
