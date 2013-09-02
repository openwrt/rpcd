cmake_minimum_required(VERSION 2.6)

PROJECT(rpcd C)
ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -g3 -Wmissing-declarations)

OPTION(FILE_SUPPORT "File plugin support" ON)
OPTION(LUCI2_SUPPORT "LuCI2 plugin support" ON)
OPTION(IWINFO_SUPPORT "libiwinfo plugin support" ON)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

IF(APPLE)
  INCLUDE_DIRECTORIES(/opt/local/include)
  LINK_DIRECTORIES(/opt/local/lib)
ENDIF()

FIND_LIBRARY(json NAMES json-c json)

ADD_EXECUTABLE(rpcd main.c exec.c session.c uci.c plugin.c)
TARGET_LINK_LIBRARIES(rpcd ubox ubus uci dl blobmsg_json ${json})

SET(PLUGINS "")

IF(FILE_SUPPORT)
  SET(PLUGINS ${PLUGINS} file_plugin)
  ADD_LIBRARY(file_plugin MODULE file.c)
  TARGET_LINK_LIBRARIES(file_plugin ubox ubus)
  SET_TARGET_PROPERTIES(file_plugin PROPERTIES OUTPUT_NAME file PREFIX "")
ENDIF()

IF(LUCI2_SUPPORT)
  SET(PLUGINS ${PLUGINS} luci2_plugin)
  ADD_LIBRARY(luci2_plugin MODULE luci2.c)
  TARGET_LINK_LIBRARIES(luci2_plugin ubox ubus)
  SET_TARGET_PROPERTIES(luci2_plugin PROPERTIES OUTPUT_NAME luci2 PREFIX "")
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
