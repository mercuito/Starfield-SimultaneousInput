// Minimal SFSE plugin: no CommonLibSF API calls, no spdlog, no hooks.
// This is a diagnostic build to isolate whether the in-Starfield LoadLibrary
// hang on plugin DLLs is caused by our static-init / DllMain code path or by
// something more universal. If THIS DLL loads cleanly inside Starfield, we
// know our prior code (CommonLibSF init, spdlog init, hook installation) was
// the offending side. If THIS DLL also hangs, the hang is independent of the
// plugin's behavior and we have a host-or-runtime issue to chase.

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
	v.UsesAddressLibrary(true);
	v.IsLayoutDependent(true);
	return v;
}();

extern "C" DLLEXPORT bool SFSEAPI SFSEPlugin_Load(const SFSE::LoadInterface*)
{
	// Intentionally empty. No logger, no AllocTrampoline, no hooks.
	// Returning true tells SFSE the load succeeded.
	return true;
}
