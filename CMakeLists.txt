cmake_minimum_required(VERSION 3.13)

file (STRINGS "VERSION" MSCP_VERSION)

project(mscp
	VERSION ${MSCP_VERSION}
	LANGUAGES C)


find_package(Git)
if (Git_FOUND)
	# based on https://github.com/nocnokneo/cmake-git-versioning-example
	execute_process(
		COMMAND	${GIT_EXECUTABLE} describe --tags --match "v*"
		OUTPUT_VARIABLE	GIT_DESCRIBE_VERSION
		RESULT_VARIABLE	GIT_DESCRIBE_ERROR_CODE
		OUTPUT_STRIP_TRAILING_WHITESPACE)
	if(NOT GIT_DESCRIBE_ERROR_CODE)
		set(MSCP_BUILD_VERSION ${GIT_DESCRIBE_VERSION})
	endif()
endif()

if (NOT MSCP_BUILD_VERSION)
	message(STATUS "Failed to determine version via Git. Use VERSION file instead.")
	set(MSCP_BUILD_VERSION v${MSCP_VERSION})
endif()


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

option(USE_PODMAN OFF) # use podman instread of docker
if(USE_PODMAN)
	message(STATUS "Use podman instead of docker")
	set(CE podman) # CE means Container Engine
else()
	set(CE docker)
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
list(APPEND MSCP_COMPILE_OPTS -iquote ${CMAKE_CURRENT_BINARY_DIR}/libssh/include)
list(APPEND MSCP_BUILD_INCLUDE_DIRS
	${mscp_SOURCE_DIR}/src
	${CMAKE_CURRENT_BINARY_DIR}/libssh/include)

list(APPEND MSCP_LINK_LIBS ssh-static)
if(BUILD_CONAN)
	find_package(ZLIB REQUIRED)
	find_package(OpenSSL REQUIRED)
	list(APPEND MSCP_LINK_LIBS ZLIB::ZLIB)
	list(APPEND MSCP_LINK_LIBS OpenSSL::Crypto)
endif()


# Symbol check
check_symbol_exists(htonll	arpa/inet.h	HAVE_HTONLL)
check_symbol_exists(ntohll	arpa/inet.h	HAVE_NTOHLL)
check_symbol_exists(strlcat	string.h	HAVE_STRLCAT)
if (NOT HAVE_STRLCAT)
	list(APPEND OPENBSD_COMPAT_SRC src/openbsd-compat/strlcat.c)
endif()


# generate config.h in build dir
configure_file(
	${mscp_SOURCE_DIR}/include/config.h.in
	${CMAKE_CURRENT_BINARY_DIR}/include/config.h)
list(APPEND MSCP_BUILD_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/include)


# libmscp.a
set(LIBMSCP_SRC
	src/mscp.c src/ssh.c src/fileops.c src/path.c src/checkpoint.c
	src/bwlimit.c src/platform.c src/print.c src/pool.c src/strerrno.c
	${OPENBSD_COMPAT_SRC})
add_library(mscp-static STATIC ${LIBMSCP_SRC})
target_include_directories(mscp-static
	PRIVATE ${MSCP_BUILD_INCLUDE_DIRS} ${mscp_SOURCE_DIR}/include)
target_compile_options(mscp-static PRIVATE ${MSCP_COMPILE_OPTS})
target_link_libraries(mscp-static PRIVATE ${MSCP_LINK_LIBS})
set_target_properties(mscp-static
	PROPERTIES
	OUTPUT_NAME	mscp)

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


install(TARGETS mscp RUNTIME DESTINATION bin)


# mscp manpage and document
configure_file(
	${mscp_SOURCE_DIR}/doc/mscp.1.in
	${PROJECT_BINARY_DIR}/mscp.1)

add_custom_target(update-rst
	COMMENT "Update doc/mscp.rst from mscp.1.in"
	WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
	COMMAND
	pandoc -s -f man mscp.1 -t rst -o ${PROJECT_SOURCE_DIR}/doc/mscp.rst)

install(FILES ${PROJECT_BINARY_DIR}/mscp.1
	DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)


# Test
add_test(NAME	pytest
	COMMAND	python3 -m pytest -v
		--mscp-path=${PROJECT_BINARY_DIR}/mscp ${PROJECT_SOURCE_DIR}/test
	WORKING_DIRECTORY	${PROJECT_BINARY_DIR})

enable_testing()




# Custom targets to build and test mscp in docker containers.
# foreach(IN ZIP_LISTS) (cmake >= 3.17) can shorten the following lists.
# However, ubuntu 20.04 has cmake 3.16.3. So this is a roundabout trick.
list(APPEND DIST_IDS	ubuntu	ubuntu	ubuntu	rocky	rocky	almalinux	alpine)
list(APPEND DIST_VERS	20.04	22.04	24.04 	8.9	9.3	9.3		3.19)

list(LENGTH DIST_IDS _DIST_LISTLEN)
math(EXPR DIST_LISTLEN "${_DIST_LISTLEN} - 1")

foreach(x RANGE ${DIST_LISTLEN})
	list(GET DIST_IDS	${x} DIST_ID)
	list(GET DIST_VERS	${x} DIST_VER)

	set(DOCKER_IMAGE mscp-${DIST_ID}:${DIST_VER})
	set(DOCKER_INDEX ${DIST_ID}-${DIST_VER})
	execute_process(
		COMMAND ${CMAKE_SOURCE_DIR}/scripts/install-build-deps.sh
		--dont-install --platform Linux-${DIST_ID}
		OUTPUT_VARIABLE REQUIREDPKGS
		OUTPUT_STRIP_TRAILING_WHITESPACE)

	add_custom_target(docker-build-${DOCKER_INDEX}
		COMMENT "Build mscp in ${DOCKER_IMAGE} container"
		WORKING_DIRECTORY ${mscp_SOURCE_DIR}
		COMMAND
		${CE} build --build-arg REQUIREDPKGS=${REQUIREDPKGS}
		-t ${DOCKER_IMAGE} -f Dockerfile/${DOCKER_INDEX}.Dockerfile .)

	add_custom_target(docker-build-${DOCKER_INDEX}-no-cache
		COMMENT "Build mscp in ${DOCKER_IMAGE} container"
		WORKING_DIRECTORY ${mscp_SOURCE_DIR}
		COMMAND
		${CE} build --build-arg REQUIREDPKGS=${REQUIREDPKGS} --no-cache
		-t ${DOCKER_IMAGE} -f Dockerfile/${DOCKER_INDEX}.Dockerfile .)

	add_custom_target(docker-test-${DOCKER_INDEX}
		COMMENT "Test mscp in ${DOCKER_IMAGE} container"
		WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
		COMMAND
		${CE} run --init --rm
		--sysctl net.ipv6.conf.all.disable_ipv6=0
		--add-host=ip6-localhost:::1
		${DOCKER_IMAGE} /mscp/scripts/test-in-container.sh)

	list(APPEND DOCKER_BUILDS		docker-build-${DOCKER_INDEX})
	list(APPEND DOCKER_BUILDS_NO_CACHE	docker-build-${DOCKER_INDEX}-no-cache)
	list(APPEND DOCKER_TESTS		docker-test-${DOCKER_INDEX})
endforeach()

add_custom_target(docker-build-all		DEPENDS ${DOCKER_BUILDS})
add_custom_target(docker-build-all-no-cache	DEPENDS ${DOCKER_BUILDS_NO_CACHE})
add_custom_target(docker-test-all		DEPENDS ${DOCKER_TESTS})


### debuild-related definitions

set(DEBBUILDCONTAINER mscp-build-deb)
execute_process(
	COMMAND ${CMAKE_SOURCE_DIR}/scripts/install-build-deps.sh
	--dont-install --platform Linux-ubuntu
	OUTPUT_VARIABLE REQUIREDPKGS_DEB
	OUTPUT_STRIP_TRAILING_WHITESPACE)

add_custom_target(build-deb
	COMMENT "build mscp deb files inside a container"
	WORKING_DIRECTORY ${mscp_SOURCE_DIR}
	BYPRODUCTS ${CMAKE_BINARY_DIR}/debbuild
	COMMAND
	${CE} build --build-arg REQUIREDPKGS=${REQUIREDPKGS_DEB}
	-t ${DEBBUILDCONTAINER} -f Dockerfile/build-deb.Dockerfile .
	COMMAND
	${CE} run --rm -v ${CMAKE_BINARY_DIR}:/out ${DEBBUILDCONTAINER}
	cp -r /debbuild /out/)


### rpmbuild-related definitions

# generate files for rpmbuild
configure_file(
	${mscp_SOURCE_DIR}/rpm/mscp.spec.in
	${mscp_SOURCE_DIR}/rpm/mscp.spec
	@ONLY)
#configure_file(
#	${mscp_SOURCE_DIR}/Dockerfile/build-srpm.Dockerfile.in
#	${mscp_SOURCE_DIR}/Dockerfile/build-srpm.Dockerfile
#	@ONLY)

# Custom target to build mscp as a src.rpm in docker.
set(RPMBUILDCONTAINER mscp-build-srpm)
set(SRPMFILE mscp-${MSCP_VERSION}-1.el9.src.rpm)
execute_process(
	COMMAND ${CMAKE_SOURCE_DIR}/scripts/install-build-deps.sh
	--dont-install --platform Linux-rocky
	OUTPUT_VARIABLE REQUIREDPKGS_RPM
	OUTPUT_STRIP_TRAILING_WHITESPACE)

add_custom_target(build-srpm
	COMMENT "Build mscp src.rpm inside a container"
	WORKING_DIRECTORY ${mscp_SOURCE_DIR}
	BYPRODUCTS ${CMAKE_BINARY_DIR}/${SRPMFILE}
	COMMAND
	${CE} build --build-arg REQUIREDPKGS=${REQUIREDPKGS_RPM}
	--build-arg MSCP_VERSION=${MSCP_VERSION}
	-t ${RPMBUILDCONTAINER} -f Dockerfile/build-srpm.Dockerfile .
	COMMAND
	${CE} run --rm -v ${CMAKE_BINARY_DIR}:/out ${RPMBUILDCONTAINER}
	cp /root/rpmbuild/SRPMS/${SRPMFILE} /out/)

### single-binary-build-related definitions

# Custom target to get single binary mscp
set(SINGLEBINARYFILE mscp.linux.${CMAKE_SYSTEM_PROCESSOR}.static)
add_custom_target(build-single-binary
	COMMENT "Build mscp as a single binary in alpine conatiner"
	WORKING_DIRECTORY ${mscp_SOURCE_DIR}
	BYPRODUCTS ${CMAKE_BINARY_DIR}/${SINGLEBINARYFILE}
	DEPENDS docker-build-alpine-3.19
	COMMAND
	${CE} run --rm -v ${CMAKE_BINARY_DIR}:/out mscp-alpine:3.19
	cp /mscp/build/mscp /out/${SINGLEBINARYFILE})


add_custom_target(build-pkg-all
	DEPENDS build-deb build-srpm build-single-binary)
