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


set(CPACK_SET_DESTDIR			true)
set(CPACK_PROJECT_NAME			${PROJECT_NAME})
set(CPACK_PROJECT_VERSION		${PROJECT_VERSION})
set(CPACK_PACKAGE_CONTACT		"Ryo Nakamura <upa@haeena.net>")

set(CPACK_DEBIAN_FILE_NAME		DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE	"https://github.com/upa/mscp")
set(CPACK_DEBIAN_PACKAGE_DEPENDS	"libssh-4")
set(CPACK_DEBIAN_PACKAGE_DESCRIPTION
	"mscp, copy files over multiple ssh connections")

include(CPack)
