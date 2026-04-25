// Minimal SFSE plugin: no CommonLibSF API calls, no spdlog, no hooks.
// This is a diagnostic build to isolate the LoadLibrary hang on plugin
// DLLs in Starfield 1.16.236 + SFSE 0.2.19.
//
// Critical find: SFSE 0.2.17+ (per sfse_whatsnew.txt) requires plugins to
// flag themselves as using "Address Library v2" via bit 1<<2 of
// addressIndependence. The shipped CommonLibSF helper UsesAddressLibrary()
// only sets bit 1<<1 (AL v1), which SFSE 0.2.19 no longer accepts. We
// write the v2 bit directly here to validate the fix.

#include "Plugin.h"
#include "SFSE/Interfaces.h"

#define DLLEXPORT __declspec(dllexport)
#define SFSEAPI __cdecl

extern "C" DLLEXPORT constexpr auto SFSEPlugin_Version = []()
{
	SFSE::PluginVersionData v{};
	v.PluginVersion(Plugin::VERSION);
	v.PluginName(Plugin::NAME);
	v.AuthorName("Parapets / minimal-test");

	// Address Library v2 flag (bit 1<<2). CommonLibSF's UsesAddressLibrary()
	// only sets v1 (bit 1<<1) which SFSE 0.2.19+ rejects. We set v2 directly.
	// Also keep v1 set for compatibility with older SFSE.
	v.UsesAddressLibrary(true);  // sets 1<<1
	v.addressIndependence |= (1u << 2); // sets 1<<2 (AL v2)

	v.IsLayoutDependent(true);
	return v;
}();

extern "C" DLLEXPORT bool SFSEAPI SFSEPlugin_Load(const SFSE::LoadInterface*)
{
	return true;
}
