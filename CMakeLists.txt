cmake_minimum_required(VERSION 3.13)

project(mscp
	VERSION 0.0.0
	LANGUAGES C)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG")

add_executable(mscp src/main.c src/platform.c src/ssh.c src/file.c src/pprint.c)
target_include_directories(mscp PUBLIC ./src /usr/local/include)
target_link_directories(mscp PUBLIC /usr/local/lib)
target_link_libraries(mscp ssh pthread m)
target_compile_definitions(mscp PUBLIC _VERSION="${PROJECT_VERSION}")

install(TARGETS mscp
	RUNTIME		DESTINATION bin
)



# Test
add_test(NAME	pytest
	COMMAND	python3 -m pytest -v
		--mscp-path=${PROJECT_BINARY_DIR}/mscp ${PROJECT_SOURCE_DIR}/test
	WORKING_DIRECTORY	${PROJECT_BINARY_DIR})

enable_testing()


# Build Packages
if(BUILD_PKG)

	# CPACK Rules
	set(CPACK_SET_DESTDIR		true)
	set(CPACK_PROJECT_NAME		${PROJECT_NAME})
	set(CPACK_PROJECT_VERSION	${PROJECT_VERSION})
	set(CPACK_PACKAGE_CONTACT	"Ryo Nakamura <upa@haeena.net>")
	set(CPACK_PACKAGE_DESCRIPTION
		"mscp, copy files over multiple ssh connections")

	# on linux
	if(UNIX AND NOT APPLE)
		execute_process(COMMAND
			bash "-c" "cat /etc/os-release|grep '^ID='|cut -d '=' -f 2|tr -d '\"'"
			OUTPUT_VARIABLE DIST_NAME OUTPUT_STRIP_TRAILING_WHITESPACE)
		execute_process(COMMAND
			bash "-c" "cat /etc/os-release|grep '^VERSION_ID='|cut -d '=' -f 2|tr -d '\"'"
			OUTPUT_VARIABLE DIST_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE)
		execute_process(COMMAND uname -p
			OUTPUT_VARIABLE ARCH OUTPUT_STRIP_TRAILING_WHITESPACE)
		set(PACKAGE_FILE_NAME
			${PROJECT_NAME}_${PROJECT_VERSION}-${DIST_NAME}-${DIST_VERSION}-${ARCH})

		set(CPACK_DEBIAN_FILE_NAME		${PACKAGE_FILE_NAME}.deb)
		set(CPACK_DEBIAN_PACKAGE_DEPENDS	"libssh-4")
		set(CPACK_DEBIAN_PACKAGE_HOMEPAGE	"https://github.com/upa/mscp")

		set(CPACK_RPM_FILE_NAME			${PACKAGE_FILE_NAME}.rpm)
		set(CPACK_RPM_PACKAGE_REQUIRES		"libssh")
		set(CPACK_RPM_PACKAGE_HOMEPAGE		"https://github.com/upa/mscp")
		set(CPACK_RPM_PACKAGE_DESCRIPTION	${CPACK_PACKAGE_DESCRIPTION})

	endif() # on linux

	include(CPack)


	# Custom commands to build mscp in docker containers

	# Ubuntu 20.04
	add_custom_target(package-ubuntu-20.04-in-docker
		COMMENT "Build mscp in ubuntu 20.04 docker container"
		WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/docker
		COMMAND docker build -t mscp-ubuntu:20.04 -f Dockerfile-ubuntu-20.04 .
		COMMAND docker run -it --rm -v ${CMAKE_BINARY_DIR}:/out mscp-ubuntu:20.04
		cp /mscp/build/mscp_${PROJECT_VERSION}-ubuntu-20.04-${ARCH}.deb /out/)

	# Ubuntu 22.04
	add_custom_target(package-ubuntu-22.04-in-docker
		COMMENT "Build mscp in ubuntu 22.04 docker container"
		WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/docker
		COMMAND docker build -t mscp-ubuntu:22.04 -f Dockerfile-ubuntu-22.04 .
		COMMAND docker run -it --rm -v ${CMAKE_BINARY_DIR}:/out mscp-ubuntu:22.04
		cp /mscp/build/mscp_${PROJECT_VERSION}-ubuntu-22.04-${ARCH}.deb /out/)

	# CentOS 8
	add_custom_target(package-centos-8-in-docker
		COMMENT "Build mscp in centos 8 docker container"
		WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/docker
		COMMAND docker build -t mscp-centos:8 -f Dockerfile-centos-8 .
		COMMAND docker run -it --rm -v ${CMAKE_BINARY_DIR}:/out mscp-centos:8
		cp /mscp/build/mscp_${PROJECT_VERSION}-centos-8-${ARCH}.rpm /out/)

	# build on all conatiners
	add_custom_target(package-all-in-docker
		COMMENT "Build mscp in all docker containers"
		DEPENDS package-ubuntu-20.04-in-docker
		DEPENDS package-ubuntu-22.04-in-docker
		DEPENDS package-centos-8-in-docker)

endif() # BUILD_PKG

