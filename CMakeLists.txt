cmake_minimum_required(VERSION 2.6)

INCLUDE(CheckFunctionExists)

PROJECT(rpcd C)
ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -g3 -Wmissing-declarations)
INCLUDE_DIRECTORIES(include)

OPTION(FILE_SUPPORT "File plugin support" ON)
OPTION(IWINFO_SUPPORT "libiwinfo plugin support" ON)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

IF(APPLE)
  INCLUDE_DIRECTORIES(/opt/local/include)
  LINK_DIRECTORIES(/opt/local/lib)
ENDIF()

CHECK_FUNCTION_EXISTS(getspnam HAVE_SHADOW)
IF(HAVE_SHADOW)
  ADD_DEFINITIONS(-DHAVE_SHADOW)
ENDIF()

FIND_LIBRARY(json NAMES json-c json)
FIND_LIBRARY(crypt NAMES crypt)
IF(crypt STREQUAL "LIBS-NOTFOUND")
  SET(crypt "")
ENDIF()

ADD_EXECUTABLE(rpcd main.c exec.c session.c uci.c plugin.c)
TARGET_LINK_LIBRARIES(rpcd ubox ubus uci dl blobmsg_json ${json} ${crypt})

SET(PLUGINS "")

IF(FILE_SUPPORT)
  SET(PLUGINS ${PLUGINS} file_plugin)
  ADD_LIBRARY(file_plugin MODULE file.c)
  TARGET_LINK_LIBRARIES(file_plugin ubox ubus)
  SET_TARGET_PROPERTIES(file_plugin PROPERTIES OUTPUT_NAME file PREFIX "")
ENDIF()

IF (IWINFO_SUPPORT)
  SET(PLUGINS ${PLUGINS} iwinfo_plugin)
  ADD_LIBRARY(iwinfo_plugin MODULE iwinfo.c)
  TARGET_LINK_LIBRARIES(iwinfo_plugin ubox ubus iwinfo)
  SET_TARGET_PROPERTIES(iwinfo_plugin PROPERTIES OUTPUT_NAME iwinfo PREFIX "")
ENDIF()

INSTALL(TARGETS rpcd ${PLUGINS}
	RUNTIME DESTINATION sbin
	LIBRARY DESTINATION lib
)
