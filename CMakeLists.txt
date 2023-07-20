cmake_minimum_required(VERSION 3.13)

file (STRINGS "VERSION" MSCP_VERSION)

project(mscp
	VERSION ${MSCP_VERSION}
	LANGUAGES C)

include(GNUInstallDirs)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG")
list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/modules)

if(APPLE)
	list(APPEND CMAKE_PREFIX_PATH /usr/local) # intel mac homebrew prefix
	list(APPEND CMAKE_PREFIX_PATH /opt/homebrew) # arm mac homebrew prefix
endif() # APPLE


option(BUILD_CONAN OFF) # Build mscp with conan
if(BUILD_CONAN)
	message(STATUS "Build mscp with conan")
endif()

option(BUILD_STATIC OFF) # Build mscp with -static LD flag
if (BUILD_STATIC)
	message(STATUS "Build mscp with -static LD option")
	if (NOT BUILD_CONAN)
		message(WARNING
			"BUILD_STATIC strongly recommended with BUILD_CONAN option")
	endif()
endif()



# add libssh static library
set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
set(WITH_SERVER OFF)
set(BUILD_SHARED_LIBS OFF)
set(WITH_EXAMPLES OFF)
set(BUILD_STATIC_LIB ON)
if(BUILD_CONAN)
	message(STATUS
		"Disable libssh GSSAPI support because libkrb5 doesn't exist in conan")
	set(WITH_GSSAPI OFF)
endif()
add_subdirectory(libssh EXCLUDE_FROM_ALL)



# setup mscp compile options
set(MSCP_COMPILE_OPTS -iquote ${CMAKE_CURRENT_BINARY_DIR}/libssh/include)
set(MSCP_BUILD_INCLUDE_DIRS
	${mscp_SOURCE_DIR}/src
	${CMAKE_CURRENT_BINARY_DIR}/libssh/include)

set(MSCP_LINK_LIBS ssh-static)
if(BUILD_CONAN)
	find_package(ZLIB REQUIRED)
	find_package(OpenSSL REQUIRED)
	list(APPEND MSCP_LINK_LIBS ZLIB::ZLIB)
	list(APPEND MSCP_LINK_LIBS OpenSSL::Crypto)
endif()

set(LIBMSCP_SRC src/mscp.c src/ssh.c src/path.c src/platform.c src/message.c)

# libmscp.so
add_library(mscp-shared SHARED ${LIBMSCP_SRC})
target_include_directories(mscp-shared
	PUBLIC	$<BUILD_INTERFACE:${mscp_SOURCE_DIR}/include>
		$<INSTALL_INTERFACE:include>
	PRIVATE ${MSCP_BUILD_INCLUDE_DIRS})
target_compile_options(mscp-shared PRIVATE ${MSCP_COMPILE_OPTS})
target_link_libraries(mscp-shared PRIVATE ${MSCP_LINK_LIBS})
set_target_properties(mscp-shared
	PROPERTIES
	OUTPUT_NAME	mscp
	PUBLIC_HEADER	${mscp_SOURCE_DIR}/include/mscp.h)

install(TARGETS mscp-shared)


# libmscp.a
add_library(mscp-static STATIC ${LIBMSCP_SRC})
target_include_directories(mscp-static
	PRIVATE ${MSCP_BUILD_INCLUDE_DIRS} ${mscp_SOURCE_DIR}/include)
target_compile_options(mscp-static PRIVATE ${MSCP_COMPILE_OPTS})
target_link_libraries(mscp-static PRIVATE ${MSCP_LINK_LIBS})
set_target_properties(mscp-static
	PROPERTIES
	OUTPUT_NAME	mscp)

install(TARGETS mscp-static)


# mscp executable
list(APPEND MSCP_LINK_LIBS m pthread)

add_executable(mscp src/main.c)
target_include_directories(mscp
	PRIVATE ${MSCP_BUILD_INCLUDE_DIRS} ${mscp_SOURCE_DIR}/include)
target_link_libraries(mscp mscp-static ${MSCP_LINK_LIBS})
if (BUILD_STATIC)
	target_link_options(mscp PRIVATE -static)
endif()
target_compile_options(mscp PRIVATE ${MSCP_COMPILE_OPTS})
target_compile_definitions(mscp PUBLIC _VERSION="${PROJECT_VERSION}")


install(TARGETS mscp RUNTIME DESTINATION bin)


# Test
add_test(NAME	pytest
	COMMAND	python3 -m pytest -v
		--mscp-path=${PROJECT_BINARY_DIR}/mscp ${PROJECT_SOURCE_DIR}/test
	WORKING_DIRECTORY	${PROJECT_BINARY_DIR})

enable_testing()



# CPACK Rules
#set(CPACK_SET_DESTDIR		true)
set(CPACK_PACKAGE_NAME		${PROJECT_NAME})
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
	execute_process(COMMAND
		bash "-c" "${mscp_SOURCE_DIR}/scripts/print-install-deps.sh ${DIST_NAME}-${DIST_VER}"
		OUTPUT_VARIABLE DIST_DEP OUTPUT_STRIP_TRAILING_WHITESPACE)

	set(PACKAGE_FILE_NAME
		${PROJECT_NAME}_${DIST_NAME}-${DIST_VER}-${ARCH})

	set(CPACK_DEBIAN_FILE_NAME		${PACKAGE_FILE_NAME}.deb)
	set(CPACK_DEBIAN_PACKAGE_DEPENDS	${DIST_DEP})
	set(CPACK_DEBIAN_PACKAGE_HOMEPAGE	"https://github.com/upa/mscp")

	set(CPACK_RPM_FILE_NAME			${PACKAGE_FILE_NAME}.rpm)
	set(CPACK_RPM_PACKAGE_REQUIRES		${DIST_DEP})
	set(CPACK_RPM_PACKAGE_HOMEPAGE		"https://github.com/upa/mscp")
	set(CPACK_RPM_PACKAGE_DESCRIPTION	${CPACK_PACKAGE_DESCRIPTION})
	set(CPACK_RPM_PACKAGE_LICENSE		"GPLv3")
endif() # on linux

include(CPack)



# Custom targets to build and test mscp in docker containers.
# foreach(IN ZIP_LISTS) (cmake >= 3.17) can shorten the following lists.
# However, ubuntu 20.04 has cmake 3.16.3. So this is a roundabout trick.
list(APPEND DIST_NAMES	ubuntu	ubuntu	rocky	almalinux	alpine)
list(APPEND DIST_VERS	20.04	22.04	8.8	8.8		3.17)
list(APPEND DIST_PKGS	deb	deb	rpm	rpm		static)

list(LENGTH DIST_NAMES _DIST_LISTLEN)
math(EXPR DIST_LISTLEN "${_DIST_LISTLEN} - 1")

foreach(x RANGE ${DIST_LISTLEN})
	list(GET DIST_NAMES	${x} DIST_NAME)
	list(GET DIST_VERS	${x} DIST_VER)
	list(GET DIST_PKGS	${x} DIST_PKG)

	set(DOCKER_IMAGE mscp-${DIST_NAME}:${DIST_VER})
	set(DOCKER_INDEX ${DIST_NAME}-${DIST_VER})
	set(PKG_FILE_NAME
		mscp_${DIST_NAME}-${DIST_VER}-${ARCH}.${DIST_PKG})

	add_custom_target(docker-build-${DOCKER_INDEX}
		COMMENT "Build mscp in ${DOCKER_IMAGE} container"
		WORKING_DIRECTORY ${mscp_SOURCE_DIR}
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

	list(APPEND DOCKER_BUILDS	docker-build-${DOCKER_INDEX})
	list(APPEND DOCKER_TESTS	docker-test-${DOCKER_INDEX})
	list(APPEND DOCKER_PKGS		docker-pkg-${DOCKER_INDEX})
endforeach()

add_custom_target(docker-build-all	DEPENDS ${DOCKER_BUILDS})
add_custom_target(docker-test-all	DEPENDS ${DOCKER_TESTS})
add_custom_target(docker-pkg-all	DEPENDS ${DOCKER_PKGS})
