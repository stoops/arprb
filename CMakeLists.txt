cmake_minimum_required(VERSION 2.8)

PROJECT(dhcprb C)
ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -g3)

ADD_EXECUTABLE(dhcprb dhcprb.c)

SET(CMAKE_INSTALL_PREFIX /usr)

INSTALL(TARGETS dhcprb
	RUNTIME DESTINATION sbin
)
