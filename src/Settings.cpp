#include "Settings.hpp"

#include "PluginConfig.hpp"

// ============================================================================================= //
// [Settings]                                                                                    //
// ============================================================================================= //

const QString Settings::iSelectionType = "0";
const QString Settings::iMaxRefCount = "0";
const QString Settings::iKeepUnsafeData = "0";
const QString Settings::iLogLevel = "1";

Settings::Settings()
    : QSettings("Randshot", PLUGIN_NAME)
{
    
}

// ============================================================================================= //
