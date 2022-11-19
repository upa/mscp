cmake_minimum_required(VERSION 3.13)

file (STRINGS "VERSION" MSCP_VERSION)

project(mscp
	VERSION ${MSCP_VERSION}
	LANGUAGES C)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG")
list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/modules)

if(APPLE)
	list(APPEND CMAKE_PREFIX_PATH /usr/local) # intel mac homebrew prefix
	list(APPEND CMAKE_PREFIX_PATH /opt/homebrew) # arm mac homebrew prefix
endif() # APPLE


# mscp executable
add_executable(mscp src/main.c src/platform.c src/ssh.c src/file.c src/pprint.c)

set(MSCP_LINK_LIBS m pthread)
set(MSCP_LINK_DIRS "")
set(MSCP_COMPILE_OPTS "")
set(MSCP_INCLUDE_DIRS ${mscp_SOURCE_DIR}/src)

if (LIBSSH_PATH)
	# libssh.a must be placed before other shared libraries for gcc
	list(APPEND MSCP_COMPILE_OPTS -iquote ${LIBSSH_PATH}/include)
	list(APPEND MSCP_INCLUDE_DIRS ${LIBSSH_PATH}/include)
	list(APPEND MSCP_LINK_DIRS ${LIBSSH_PATH}/lib)
	list(APPEND MSCP_LINK_LIBS libssh.a)

	find_package(GSSAPI)
	list(APPEND MSCP_LINK_LIBS ${GSSAPI_LIBRARIES})

	find_package(OpenSSL)
	list(APPEND MSCP_LINK_LIBS ${OPENSSL_LIBRARIES})

	find_package(ZLIB)
	list(APPEND MSCP_LINK_LIBS ${ZLIB_LIBRARIES})
else()
	find_package(libssh REQUIRED)
	list(APPEND MSCP_LINK_LIBS ssh)
endif()

if (WITH_ASYNC_WRITE)
	target_compile_definitions(mscp PUBLIC ASYNC_WRITE=1)
endif()

target_include_directories(mscp PRIVATE ${MSCP_INCLUDE_DIRS})
target_link_directories(mscp PRIVATE ${MSCP_LINK_DIRS})
target_link_libraries(mscp PRIVATE ${MSCP_LINK_LIBS})
target_compile_options(mscp PRIVATE ${MSCP_COMPILE_OPTS})
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



# CPACK Rules
set(CPACK_SET_DESTDIR		true)
set(CPACK_PROJECT_NAME		${PROJECT_NAME})
set(CPACK_PROJECT_VERSION	${PROJECT_VERSION})
set(CPACK_PACKAGE_CONTACT	"Ryo Nakamura <upa@haeena.net>")
set(CPACK_PACKAGE_DESCRIPTION
	"mscp, copy files over multiple ssh connections")

execute_process(COMMAND uname -m
	OUTPUT_VARIABLE ARCH OUTPUT_STRIP_TRAILING_WHITESPACE)

if(UNIX AND NOT APPLE) # on linux
	execute_process(COMMAND
		bash "-c" "cat /etc/os-release|grep '^ID='|cut -d '=' -f 2|tr -d '\"'"
		OUTPUT_VARIABLE DIST_NAME OUTPUT_STRIP_TRAILING_WHITESPACE)
	execute_process(COMMAND
		bash "-c" "cat /etc/os-release|grep '^VERSION_ID='|cut -d '=' -f 2|tr -d '\"'"
		OUTPUT_VARIABLE DIST_VER OUTPUT_STRIP_TRAILING_WHITESPACE)
	set(PACKAGE_FILE_NAME
		${PROJECT_NAME}_${PROJECT_VERSION}-${DIST_NAME}-${DIST_VER}-${ARCH})

	set(CPACK_DEBIAN_FILE_NAME		${PACKAGE_FILE_NAME}.deb)
	set(CPACK_DEBIAN_PACKAGE_DEPENDS	"libssh-4")
	set(CPACK_DEBIAN_PACKAGE_HOMEPAGE	"https://github.com/upa/mscp")

	set(CPACK_RPM_FILE_NAME			${PACKAGE_FILE_NAME}.rpm)
	set(CPACK_RPM_PACKAGE_REQUIRES		"libssh")
	set(CPACK_RPM_PACKAGE_HOMEPAGE		"https://github.com/upa/mscp")
	set(CPACK_RPM_PACKAGE_DESCRIPTION	${CPACK_PACKAGE_DESCRIPTION})
endif() # on linux

include(CPack)



# Custom targets to build and test mscp in docker containers.
# foreach(IN ZIP_LISTS) (cmake >= 3.17) can shorten the following lists.
# However, ubuntu 20.04 has cmake 3.16.3.
list(APPEND DIST_NAMES	ubuntu)
list(APPEND DIST_VERS	20.04)
list(APPEND DIST_PKGS	deb)

list(APPEND DIST_NAMES	ubuntu)
list(APPEND DIST_VERS	22.04)
list(APPEND DIST_PKGS	deb)

list(APPEND DIST_NAMES	centos)
list(APPEND DIST_VERS	8)
list(APPEND DIST_PKGS	rpm)

list(APPEND DIST_NAMES	rocky)
list(APPEND DIST_VERS	8.6)
list(APPEND DIST_PKGS	rpm)

foreach(x RANGE 3)
	list(GET DIST_NAMES	${x} DIST_NAME)
	list(GET DIST_VERS	${x} DIST_VER)
	list(GET DIST_PKGS	${x} DIST_PKG)
	set(DOCKER_IMAGE mscp-${DIST_NAME}:${DIST_VER})
	set(DOCKER_INDEX ${DIST_NAME}-${DIST_VER})
	set(PKG_FILE_NAME
		mscp_${PROJECT_VERSION}-${DIST_NAME}-${DIST_VER}-${ARCH}.${DIST_PKG})

	add_custom_target(docker-build-${DOCKER_INDEX}
		COMMENT "Build mscp in ${DOCKER_IMAGE} container"
		WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
		COMMAND
		docker build -t ${DOCKER_IMAGE} -f docker/${DOCKER_INDEX}.Dockerfile .)

	add_custom_target(docker-test-${DOCKER_INDEX}
		COMMENT "Test mscp in ${DOCKER_IMAGE} container"
		WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
		COMMAND
		docker run --init --rm ${DOCKER_IMAGE} /mscp/scripts/test-in-container.sh)

	add_custom_target(docker-pkg-${DOCKER_INDEX}
		COMMENT "Retrieve mscp package from ${DOCKER_IMAGE} container"
		WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
		COMMAND
		docker run --rm -v ${CMAKE_BINARY_DIR}:/out ${DOCKER_IMAGE}
		cp /mscp/build/${PKG_FILE_NAME} /out/)
endforeach()
