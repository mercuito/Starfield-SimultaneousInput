cmake_minimum_required(VERSION 3.30)

project(
	SimultaneousInput
	VERSION 1.2.0
	LANGUAGES CXX
)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Generate a debug PDB even for Release. SFSE plugin crashes on a user's
# machine come back as minidumps that need symbol resolution.
set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "ProgramDatabase")

# === Build provenance: git SHA + build date embedded in DLL ===
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

# ============================================================================
# libxse/CommonLibSF + libxse/commonlib-shared
# ----------------------------------------------------------------------------
# These submodules ship only an xmake.lua. We build them as static libs via
# CMake here so the rest of the project can keep using CMake + vcpkg. The
# layout matches what xmake does: commonlib-shared compiles its src/**.cpp
# into a static lib and exposes include/, then CommonLibSF compiles its own
# src/**.cpp + links commonlib-shared, exposing its own include/.
#
# Source of truth on dependency graph:
#   external/CommonLibSF/xmake.lua          (commonlibsf target)
#   external/CommonLibSF/lib/commonlib-shared/xmake.lua (commonlib-shared target)
# ============================================================================
set(CLIBSF_DIR     ${CMAKE_CURRENT_SOURCE_DIR}/external/CommonLibSF)
set(CLIBSHARED_DIR ${CLIBSF_DIR}/lib/commonlib-shared)

find_package(spdlog CONFIG REQUIRED)

# --- commonlib-shared ---
file(
	GLOB_RECURSE COMMONLIB_SHARED_SOURCES
	CONFIGURE_DEPENDS
	${CLIBSHARED_DIR}/src/*.cpp
)
add_library(commonlib-shared STATIC ${COMMONLIB_SHARED_SOURCES})
target_include_directories(commonlib-shared SYSTEM PUBLIC ${CLIBSHARED_DIR}/include)
target_compile_features(commonlib-shared PUBLIC cxx_std_23)
# REX/BASE.h pulls in all std headers (cstdint, format, etc) and is the de-facto
# PCH for the libxse code. Force-include so individual TUs don't have to.
target_precompile_headers(commonlib-shared PRIVATE
	${CLIBSHARED_DIR}/include/REX/BASE.h
)
target_compile_definitions(commonlib-shared PUBLIC
	WINVER=0x0A00
	_WIN32_WINNT=0x0A00
	WIN32_LEAN_AND_MEAN
	NOMINMAX
	_ITERATOR_DEBUG_LEVEL=0
)
# spdlog: link compiled vcpkg variant (avoids windows.h pulling in via header-
# only mode and breaking REX::W32::MAX_PATH expansion via macro pollution).
# Keep SPDLOG_WCHAR_TO_UTF8_SUPPORT public so libxse's REX::LOG.cpp wstring_view
# log overloads are visible at every TU. SPDLOG_USE_STD_FORMAT is NOT required
# here: libxse pre-formats via std::vformat before calling spdlog with plain
# string_view, so we keep spdlog's default fmt backend.
target_link_libraries(commonlib-shared PUBLIC spdlog::spdlog)
# spdlog rebuilt with wchar feature in vcpkg.json -> SPDLOG_WCHAR_TO_UTF8_SUPPORT
# is compiled into the lib. We mirror it on the consumer side so the wstring_view
# log overloads in spdlog headers are visible.
# We do NOT define SPDLOG_WCHAR_FILENAMES (filename_t stays std::string), so
# libxse's API.cpp passing path->string() to file sinks compiles cleanly.
target_compile_definitions(commonlib-shared PUBLIC
	SPDLOG_WCHAR_TO_UTF8_SUPPORT
)
target_link_libraries(commonlib-shared PUBLIC
	advapi32.lib bcrypt.lib dbghelp.lib dxgi.lib ole32.lib
	shell32.lib user32.lib version.lib ws2_32.lib
)
if(MSVC)
	target_compile_options(commonlib-shared PUBLIC /bigobj)
	# Vendored code; do not gate the build on its warnings.
	target_compile_options(commonlib-shared PRIVATE
		/wd4005 /wd4068 /wd4200 /wd4201 /wd4244 /wd4267 /wd4324 /wd4458 /wd4505
	)
endif()

# --- CommonLibSF ---
file(
	GLOB_RECURSE COMMONLIBSF_SOURCES
	CONFIGURE_DEPENDS
	${CLIBSF_DIR}/src/*.cpp
)
add_library(CommonLibSF STATIC ${COMMONLIBSF_SOURCES})
target_include_directories(CommonLibSF SYSTEM PUBLIC ${CLIBSF_DIR}/include)
target_compile_features(CommonLibSF PUBLIC cxx_std_23)
target_link_libraries(CommonLibSF PUBLIC commonlib-shared)
target_precompile_headers(CommonLibSF PRIVATE
	${CLIBSF_DIR}/include/SFSE/Impl/PCH.h
)
if(MSVC)
	target_compile_options(CommonLibSF PUBLIC /bigobj)
	target_compile_options(CommonLibSF PRIVATE
		/wd4005 /wd4068 /wd4200 /wd4201 /wd4244 /wd4267 /wd4324 /wd4458 /wd4505
	)
endif()
add_library(CommonLibSF::CommonLibSF ALIAS CommonLibSF)

# ============================================================================
# Plugin target
# ============================================================================
add_library(${PROJECT_NAME} SHARED)

file(
	GLOB_RECURSE HEADER_FILES
	LIST_DIRECTORIES false
	CONFIGURE_DEPENDS
	"${CMAKE_CURRENT_SOURCE_DIR}/src/*.h"
)
target_sources(${PROJECT_NAME} PRIVATE ${HEADER_FILES})

file(
	GLOB_RECURSE SOURCE_FILES
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

if(MSVC)
	# Plugin code held to /WX. Vendored libxse code already has
	# warnings suppressed via /external:W0 + SYSTEM include.
	target_compile_options(
		${PROJECT_NAME}
		PRIVATE
		"/sdl"
		"/utf-8"
		"/Zi"
		"/permissive-"
		"/Zc:preprocessor"
		"/W4"
		"/WX"
		"/experimental:external"
		"/external:anglebrackets"
		"/external:W0"
		"/wd4200"
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

target_link_libraries(
	${PROJECT_NAME}
	PRIVATE
	CommonLibSF::CommonLibSF
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
