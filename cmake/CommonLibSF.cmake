# cmake/CommonLibSF.cmake
#
# Hand-rolled CMake wrapper around libxse/CommonLibSF (and its nested
# libxse/commonlib-shared submodule). The libxse repos ship XMake build files
# only; rather than pivot the whole project to XMake we compile their sources
# directly into two static libraries here:
#
#   commonlib-shared   <- external/CommonLibSF/lib/commonlib-shared/src/**.cpp
#   CommonLibSF        <- external/CommonLibSF/src/**.cpp  (depends on commonlib-shared)
#
# Both expose their respective include/ trees as PUBLIC SYSTEM include
# directories so consumer code (our plugin) sees them as third-party headers,
# letting MSVC's /external:W0 suppress warnings inside vendored code without
# disabling them in our own.
#
# Background: the prior submodule (Starfield-Reverse-Engineering/CommonLibSF,
# pinned at f2ea130) only parses Address Library DB format 2 in
# REL::IDDatabase, so Starfield 1.15.x's format-5 AL DB triggered:
#   [critical] Unsupported address library format: 5
# libxse/CommonLibSF replaces that with a HEADER_V5 path in
# lib/commonlib-shared/src/REL/IDDB.cpp. This wrapper is the bridge that lets
# us consume that fix without rewriting the build system.

if(NOT EXISTS "${CMAKE_CURRENT_LIST_DIR}/../external/CommonLibSF/CMakeLists.txt"
   AND NOT EXISTS "${CMAKE_CURRENT_LIST_DIR}/../external/CommonLibSF/xmake.lua")
	message(FATAL_ERROR
		"external/CommonLibSF is not initialized. "
		"Run: git submodule update --init --recursive")
endif()

set(_clsf_root          "${CMAKE_CURRENT_LIST_DIR}/../external/CommonLibSF")
set(_clshared_root      "${_clsf_root}/lib/commonlib-shared")

if(NOT EXISTS "${_clshared_root}/xmake.lua")
	message(FATAL_ERROR
		"external/CommonLibSF/lib/commonlib-shared is not initialized. "
		"Run: git submodule update --init --recursive")
endif()

# spdlog is a public dep of commonlib-shared (REX::Impl::Log routes through
# spdlog::default_logger_raw). Pulled via vcpkg manifest in vcpkg.json.
find_package(spdlog CONFIG REQUIRED)

# === commonlib-shared ===
file(GLOB_RECURSE _clshared_sources
	CONFIGURE_DEPENDS
	"${_clshared_root}/src/*.cpp"
)
file(GLOB_RECURSE _clshared_headers
	CONFIGURE_DEPENDS
	"${_clshared_root}/include/*.h"
)

add_library(commonlib-shared STATIC
	${_clshared_sources}
	${_clshared_headers}
)
add_library(CommonLibSF::commonlib-shared ALIAS commonlib-shared)

target_compile_features(commonlib-shared PUBLIC cxx_std_23)
set_target_properties(commonlib-shared PROPERTIES CXX_EXTENSIONS OFF)

# PUBLIC SYSTEM so warnings inside libxse headers don't fail our /WX build.
target_include_directories(commonlib-shared SYSTEM PUBLIC
	"${_clshared_root}/include"
)

target_link_libraries(commonlib-shared PUBLIC spdlog::spdlog)

# Mirror commonlib-shared/xmake.lua add_syslinks(...).
if(WIN32)
	target_link_libraries(commonlib-shared PUBLIC
		advapi32
		bcrypt
		d3d11
		d3dcompiler
		dbghelp
		dxgi
		ole32
		shell32
		user32
		version
		ws2_32
	)
endif()

if(MSVC)
	# spdlog config alignment with vcpkg's binary build:
	# vcpkg ships spdlog without SPDLOG_WCHAR_FILENAMES so its file_sink ABI
	# uses std::string (not std::wstring) for filenames. We deliberately do
	# NOT define SPDLOG_WCHAR_FILENAMES on consumers here; defining it would
	# flip the consumer-side filename_t type and produce
	#   error C2665: spdlog::sinks::basic_file_sink::basic_file_sink: no
	#   overloaded function could convert all the argument types
	# at the std::construct_at call inside <xutility>. SPDLOG_USE_STD_FORMAT
	# is similarly skipped: we accept fmtlib by default which is what vcpkg
	# builds spdlog against.
	#
	# REX::FAIL with wstring_view still works because its impl funnels through
	# spdlog::default_logger_raw()->log(...), which is template-instantiated
	# in commonlib-shared's REX/LOG.cpp (non-WCHAR ABI). The only thing we
	# lose is wstring filenames; we don't use those.
	target_compile_options(commonlib-shared PRIVATE
		/utf-8
		/permissive-
		/Zc:preprocessor
		/EHsc
		/bigobj
	)

	# commonlib-shared sources rely on the PCH (REX/BASE.h via src/REX/PCH.h)
	# for all of <cstdint>, <cstdarg>, <ranges>, <format>, etc. Without it the
	# standard headers (vcruntime.h's __report_gsfailure declaration, ucrt's
	# corecrt_wstdio.h va_list usage) fail with C2065 'uintptr_t': undeclared
	# identifier and friends. xmake.lua sets set_pcxxheader("src/REX/PCH.h"),
	# so we mirror that here.
	target_precompile_headers(commonlib-shared PRIVATE
		"${_clshared_root}/src/REX/PCH.h"
	)
endif()

# === CommonLibSF ===
file(GLOB_RECURSE _clsf_sources
	CONFIGURE_DEPENDS
	"${_clsf_root}/src/*.cpp"
)
file(GLOB_RECURSE _clsf_headers
	CONFIGURE_DEPENDS
	"${_clsf_root}/include/*.h"
)

add_library(CommonLibSF STATIC
	${_clsf_sources}
	${_clsf_headers}
)
add_library(CommonLibSF::CommonLibSF ALIAS CommonLibSF)

target_compile_features(CommonLibSF PUBLIC cxx_std_23)
set_target_properties(CommonLibSF PROPERTIES CXX_EXTENSIONS OFF)

target_include_directories(CommonLibSF SYSTEM PUBLIC
	"${_clsf_root}/include"
)

target_link_libraries(CommonLibSF PUBLIC commonlib-shared)

if(MSVC)
	target_compile_options(CommonLibSF PRIVATE
		/utf-8
		/permissive-
		/Zc:preprocessor
		/EHsc
	)
	# CommonLibSF's PCH at include/SFSE/Impl/PCH.h. The xmake.lua ships this as
	# pch; replicate so generated IDs_*.h don't recompile in every TU.
	target_precompile_headers(CommonLibSF PRIVATE
		"${_clsf_root}/include/SFSE/Impl/PCH.h"
	)
endif()

unset(_clsf_root)
unset(_clshared_root)
unset(_clsf_sources)
unset(_clsf_headers)
unset(_clshared_sources)
unset(_clshared_headers)
