cmake_minimum_required(VERSION 3.30)

project(
	SimultaneousInput
	VERSION 1.1.0
	LANGUAGES CXX
)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Generate a debug PDB even for Release: SFSE plugin crashes on a user's
# machine come back as minidumps that need symbol resolution. The cost is
# disk space; the benefit is "we can actually diagnose what failed".
set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "ProgramDatabase")

# === Build provenance: git SHA + build date embedded in DLL ===
# Captured at configure time. Re-run CMake configure to refresh after a
# new commit (CI does this on every push, so deployed artifacts always
# match HEAD). Falls back to "unknown" if git is missing rather than
# failing the build, so out-of-tree archives still build.
find_package(Git QUIET)
if(Git_FOUND)
	execute_process(
		COMMAND "${GIT_EXECUTABLE}" rev-parse --short=12 HEAD
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
		OUTPUT_VARIABLE SIMULTANEOUSINPUT_GIT_SHA
		OUTPUT_STRIP_TRAILING_WHITESPACE
		ERROR_QUIET
	)
endif()
if(NOT SIMULTANEOUSINPUT_GIT_SHA)
	set(SIMULTANEOUSINPUT_GIT_SHA "unknown")
endif()
string(TIMESTAMP SIMULTANEOUSINPUT_BUILD_DATE "%Y-%m-%dT%H:%M:%SZ" UTC)
set(SIMULTANEOUSINPUT_COMPANY "Parapets / Exit-9B (fork: gitlostinit)")

cmake_host_system_information(
	RESULT Starfield_PATH
	QUERY WINDOWS_REGISTRY "HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/Steam App 1716740"
	VALUE "InstallLocation"
)

set(Starfield_PATH ${Starfield_PATH} CACHE PATH "Installed path of Starfield.")
set(GAME_DIR ${Starfield_PATH})

add_library(${PROJECT_NAME} SHARED)

file(
	GLOB_RECURSE
	HEADER_FILES
	LIST_DIRECTORIES false
	CONFIGURE_DEPENDS
	"${CMAKE_CURRENT_SOURCE_DIR}/src/*.h"
)

target_sources(${PROJECT_NAME} PRIVATE ${HEADER_FILES})

file(
	GLOB_RECURSE
	SOURCE_FILES
	LIST_DIRECTORIES false
	CONFIGURE_DEPENDS
	"${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
)

target_sources(${PROJECT_NAME} PRIVATE ${SOURCE_FILES})

target_sources(
	${PROJECT_NAME}
	PRIVATE
	.clang-format
	.editorconfig
	vcpkg.json
)

configure_file(
	${CMAKE_CURRENT_SOURCE_DIR}/cmake/Plugin.h.in
	${CMAKE_CURRENT_BINARY_DIR}/src/Plugin.h
	@ONLY
)

configure_file(
	${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.rc.in
	${CMAKE_CURRENT_BINARY_DIR}/version.rc
	@ONLY
)

target_sources(
	${PROJECT_NAME}
	PRIVATE
	${CMAKE_CURRENT_BINARY_DIR}/version.rc
)

target_include_directories(
	${PROJECT_NAME}
	PRIVATE
	${CMAKE_CURRENT_BINARY_DIR}/src
	${CMAKE_CURRENT_SOURCE_DIR}/src
)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
	# Plugin code is held to /WX. CommonLibSF (added below) is allowed to emit
	# warnings without failing the build via /external:W0.
	target_compile_options(
		${PROJECT_NAME}
		PRIVATE
		"/sdl" # additional security checks
		"/utf-8"
		"/Zi"

		"/permissive-"
		"/Zc:preprocessor"

		"/W4"
		"/WX"

		# /external:* lets us scope warnings: external angle-bracket includes
		# (CommonLibSF, spdlog) compile under W0; our own quote includes get W4.
		"/experimental:external"
		"/external:anglebrackets"
		"/external:W0"

		"/wd4200" # nonstandard extension used: zero-sized array in struct/union (used in SFSE/CommonLibSF headers)

		"$<$<CONFIG:DEBUG>:>"
		"$<$<CONFIG:RELEASE>:/Zc:inline;/JMC-;/Ob3>"
		"$<$<CONFIG:RELWITHDEBINFO>:/Zc:inline;/JMC-;/Ob3>"
	)

	target_link_options(
		${PROJECT_NAME}
		PRIVATE
		"$<$<CONFIG:DEBUG>:/INCREMENTAL;/OPT:NOREF;/OPT:NOICF>"
		"$<$<CONFIG:RELEASE>:/INCREMENTAL:NO;/OPT:REF;/OPT:ICF;/DEBUG:FULL>"
		"$<$<CONFIG:RELWITHDEBINFO>:/INCREMENTAL:NO;/OPT:REF;/OPT:ICF;/DEBUG:FULL>"
	)
endif()

# === libxse/CommonLibSF (+ libxse/commonlib-shared) ===
#
# The submodule at external/CommonLibSF is libxse/CommonLibSF, which is
# XMake-based and ships no top-level CMakeLists.txt. cmake/CommonLibSF.cmake
# hand-rolls equivalent CMake static-lib targets for both
# libxse/CommonLibSF and its nested libxse/commonlib-shared submodule.
#
# We adopted libxse to get Address Library DB format-5 parsing
# (REL::IDDatabase HEADER_V5 in commonlib-shared/src/REL/IDDB.cpp). The
# previously vendored Starfield-Reverse-Engineering/CommonLibSF only
# parsed format 2 and crashed on Starfield 1.15.x's format-5 AL DBs with:
#   [critical] Unsupported address library format: 5
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/CommonLibSF.cmake)

target_link_libraries(
	${PROJECT_NAME}
	PRIVATE
	CommonLibSF::CommonLibSF
	spdlog::spdlog
)

if(CMAKE_GENERATOR MATCHES "Visual Studio")
	option(CMAKE_VS_INCLUDE_INSTALL_TO_DEFAULT_BUILD "Include INSTALL target to default build." OFF)
endif()

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
	set(CMAKE_INSTALL_PREFIX "${GAME_DIR}/Data" CACHE PATH
		"Install path prefix (e.g. Starfield Data directory or Mod Organizer virtual directory)."
		FORCE
	)
endif()

install(
	FILES
	"$<TARGET_FILE:${PROJECT_NAME}>"
	"$<TARGET_PDB_FILE:${PROJECT_NAME}>"
	DESTINATION "SFSE/Plugins"
	COMPONENT SFSEPlugin
)

set(CPACK_GENERATOR "7Z")
set(CPACK_PACKAGE_FILE_NAME ${PROJECT_NAME}-${PROJECT_VERSION})
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY FALSE)
include(CPack)
