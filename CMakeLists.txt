cmake_minimum_required(VERSION 2.6)

INCLUDE(CheckFunctionExists)

PROJECT(rpcd C)
ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -g3 -Wmissing-declarations -DINSTALL_PREFIX="${CMAKE_INSTALL_PREFIX}")
INCLUDE_DIRECTORIES(include)

OPTION(FILE_SUPPORT "File plugin support" ON)
OPTION(IWINFO_SUPPORT "libiwinfo plugin support" ON)
OPTION(RPCSYS_SUPPORT "rpc-sys plugin support" ON)
OPTION(UCODE_SUPPORT "ucode plugin support" ON)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

IF(APPLE)
  INCLUDE_DIRECTORIES(/opt/local/include)
  LINK_DIRECTORIES(/opt/local/lib)
ENDIF()

CHECK_FUNCTION_EXISTS(getspnam HAVE_SHADOW)
IF(HAVE_SHADOW)
  ADD_DEFINITIONS(-DHAVE_SHADOW)
ENDIF()

FIND_LIBRARY(uci NAMES uci)
FIND_LIBRARY(ubus NAMES ubus)
FIND_LIBRARY(ubox NAMES ubox)
FIND_LIBRARY(blobmsg_json NAMES blobmsg_json)
FIND_LIBRARY(json NAMES json-c json)
FIND_LIBRARY(crypt NAMES crypt)
IF(crypt STREQUAL "crypt-NOTFOUND")
  SET(crypt "")
ENDIF()

FIND_PATH(ubus_include_dir libubus.h)
INCLUDE_DIRECTORIES(${ubus_include_dir})

FIND_PATH(ubox_include_dir libubox/blobmsg_json.h)
INCLUDE_DIRECTORIES(${ubox_include_dir})

ADD_EXECUTABLE(rpcd main.c exec.c session.c uci.c rc.c plugin.c)
TARGET_LINK_LIBRARIES(rpcd ${ubox} ${ubus} ${uci} ${blobmsg_json} ${json} ${crypt} dl)

SET(PLUGINS "")

IF(FILE_SUPPORT)
  SET(PLUGINS ${PLUGINS} file_plugin)
  ADD_LIBRARY(file_plugin MODULE file.c)
  TARGET_LINK_LIBRARIES(file_plugin ${ubox} ${ubus})
  SET_TARGET_PROPERTIES(file_plugin PROPERTIES OUTPUT_NAME file PREFIX "")
ENDIF()

IF(RPCSYS_SUPPORT)
  SET(PLUGINS ${PLUGINS} rpcsys_plugin)
  ADD_LIBRARY(rpcsys_plugin MODULE sys.c)
  TARGET_LINK_LIBRARIES(rpcsys_plugin ${ubox} ${ubus})
  SET_TARGET_PROPERTIES(rpcsys_plugin PROPERTIES OUTPUT_NAME rpcsys PREFIX "")
ENDIF()

IF(IWINFO_SUPPORT)
  FIND_LIBRARY(iwinfo NAMES iwinfo)
  SET(PLUGINS ${PLUGINS} iwinfo_plugin)
  ADD_LIBRARY(iwinfo_plugin MODULE iwinfo.c)
  TARGET_LINK_LIBRARIES(iwinfo_plugin ${ubox} ${ubus} ${iwinfo})
  SET_TARGET_PROPERTIES(iwinfo_plugin PROPERTIES OUTPUT_NAME iwinfo PREFIX "")
ENDIF()

IF(UCODE_SUPPORT)
  FIND_LIBRARY(ucode NAMES ucode)
  SET(PLUGINS ${PLUGINS} ucode_plugin)
  ADD_LIBRARY(ucode_plugin MODULE ucode.c)
  TARGET_LINK_LIBRARIES(ucode_plugin ${ucode})
  SET_TARGET_PROPERTIES(ucode_plugin PROPERTIES OUTPUT_NAME ucode PREFIX "")
ENDIF()

INSTALL(TARGETS rpcd ${PLUGINS}
	RUNTIME DESTINATION sbin
	LIBRARY DESTINATION lib/rpcd
)
