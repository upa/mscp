cmake_minimum_required(VERSION 3.13)

project(mscp VERSION 0.0.0 LANGUAGES C)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG")

add_executable(mscp src/main.c src/platform.c src/ssh.c src/file.c src/pprint.c)
target_include_directories(mscp PUBLIC ./src /usr/local/include)
target_link_directories(mscp PUBLIC /usr/local/lib)
target_link_libraries(mscp ssh pthread m)
target_compile_definitions(mscp PUBLIC _VERSION="${PROJECT_VERSION}")

install(TARGETS mscp
	RUNTIME		DESTINATION bin
)

if(BUILD_PKG)

	set(CPACK_SET_DESTDIR			true)
	set(CPACK_PROJECT_NAME			${PROJECT_NAME})
	set(CPACK_PROJECT_VERSION		${PROJECT_VERSION})
	set(CPACK_PACKAGE_CONTACT		"Ryo Nakamura <upa@haeena.net>")
	set(CPACK_PACKAGE_DESCRIPTION
		"mscp, copy files over multiple ssh connections")

	# on linux
	if(UNIX AND NOT APPLE)
		execute_process(COMMAND
			bash "-c" "cat /etc/os-release|grep '^ID='|cut -d '=' -f 2"
			OUTPUT_VARIABLE DIST_NAME OUTPUT_STRIP_TRAILING_WHITESPACE)
		execute_process(COMMAND
			bash "-c" "cat /etc/os-release|grep '^VERSION_ID='|cut -d '=' -f 2|tr -d '\"'"
			OUTPUT_VARIABLE DIST_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE)
		execute_process(COMMAND uname -p
			OUTPUT_VARIABLE ARCH OUTPUT_STRIP_TRAILING_WHITESPACE)
		set(PACKAGE_FILE_NAME
			${PROJECT_NAME}_${PROJECT_VERSION}-${DIST_NAME}-${DIST_VERSION}-${ARCH})

		set(CPACK_DEBIAN_FILE_NAME		${PACKAGE_FILE_NAME}.deb)
		set(CPACK_DEBIAN_PACKAGE_HOMEPAGE	"https://github.com/upa/mscp")
		set(CPACK_DEBIAN_PACKAGE_DEPENDS	"libssh-4")
	endif() # on linux

	include(CPack)
endif() # BUILD_PKG defined

