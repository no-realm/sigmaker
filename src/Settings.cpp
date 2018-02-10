#include "Settings.hpp"

#include "PluginConfig.hpp"

// ============================================================================================= //
// [Settings]                                                                                    //
// ============================================================================================= //

const QString Settings::selection_type = "selection_type";
const QString Settings::max_ref_count = "max_ref_count";
const QString Settings::keep_unsafe_data = "keep_unsafe_data";
const QString Settings::log_level = "log_level";

Settings::Settings()
    : QSettings("Randshot", PLUGIN_NAME)
{
    
}

// ============================================================================================= //
