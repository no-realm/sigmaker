#include "Utils.hpp"

#include "PluginConfig.hpp"
#include "Core.hpp"

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <diskio.hpp>
#include <functional>

// ============================================================================================= //

/**
 * @brief   Initialization callback for IDA.
 * @return  A @c PLUGIN_ constant from loader.hpp.
 */
int idaapi init()
{
    if (!is_idaq()) return PLUGIN_SKIP;
    if (inf.filetype != f_PE) return PLUGIN_SKIP;
    msg("[" PLUGIN_NAME "] " PLUGIN_TEXTUAL_VERSION " by Randshot loaded!\n");

    try
    {
        Core::instance().init_plugin();
    }
    catch (const std::runtime_error &e)
    {
        msg("[" PLUGIN_NAME "][ERROR] Cannot load plugin: %s\n", e.what());
        return PLUGIN_UNL;
    }

    return PLUGIN_KEEP;
}

/**
 * @brief   Run callback for IDA.
 */
#if IDP_INTERFACE_VERSION >= 700
    bool idaapi run(size_t)
#else
    void idaapi run(int)
#endif
{
    Core::instance().run_plugin();
#if IDP_INTERFACE_VERSION >= 700
    return true;
#endif
}

/**
 * @brief   Shutdown callback for IDA.
 */
void idaapi term()
{
    if (Core::isInstantiated())
    {
        Core::freeInstance();
    }
}

plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    PLUGIN_KEEP,
    &init,
    &term,
    &run,
    "Creates unique signatures",
    "Plugin providing interface for creating unique signature.",
    PLUGIN_NAME ": Options",
    "Ctrl-Alt-S"
};

// ============================================================================================= //
