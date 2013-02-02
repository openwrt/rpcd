cmake_minimum_required(VERSION 2.6)

PROJECT(luci-rpcd C)
ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -g3 -Wmissing-declarations)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

IF(APPLE)
  INCLUDE_DIRECTORIES(/opt/local/include)
  LINK_DIRECTORIES(/opt/local/lib)
ENDIF()

ADD_EXECUTABLE(luci-rpcd main.c session.c file.c uci.c)
TARGET_LINK_LIBRARIES(luci-rpcd ubox ubus uci)

SET(CMAKE_INSTALL_PREFIX /usr)

INSTALL(TARGETS luci-rpcd
	RUNTIME DESTINATION sbin
)
