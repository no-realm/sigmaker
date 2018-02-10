#include "Core.hpp"

#include "PluginConfig.hpp"
#include "Settings.hpp"
#include "Generator.hpp"
#include "Searcher.hpp"

#include <idp.hpp>


// ============================================================================================= //
// [Core]                                                                                        //
// ============================================================================================= //

void Core::init_plugin()
{
    Settings settings;

    auto log_level_var = settings.value(Settings::log_level, 1);
    auto log_level = 1;

    if (log_level_var.canConvert<int>()) log_level = log_level_var.toInt();
    else settings.remove(Settings::log_level);

    if (log_level >= 3)
    {
        auto selection_type_var = settings.value(Settings::selection_type, 0);
        auto max_ref_count_var = settings.value(Settings::max_ref_count, 0);
        auto keep_unsafe_data_var = settings.value(Settings::keep_unsafe_data, 1);

        auto selection_type = 0;
        auto max_ref_count = 0;
        auto keep_unsafe_data = 1;

        if (selection_type_var.canConvert<int>()) selection_type = selection_type_var.toInt();
        else settings.remove(Settings::selection_type);

        if (max_ref_count_var.canConvert<int>()) max_ref_count = max_ref_count_var.toInt();
        else settings.remove(Settings::max_ref_count);

        if (keep_unsafe_data_var.canConvert<int>()) keep_unsafe_data = keep_unsafe_data_var.toInt();
        else settings.remove(Settings::keep_unsafe_data);

        msg("[" PLUGIN_NAME "] Current Settings:\n");
        msg("-    Selection Type: %i\n", selection_type);
        msg("-    Max Reference Count: %i\n", max_ref_count);
        msg("-    Keep Unsafe Data: %i\n", keep_unsafe_data);
        msg("-    Log Level: %i\n", log_level);
    }
}

void Core::run_plugin()
{
    open_options_dialog();
}

void Core::open_options_dialog()
{
    auto selected_action = 0;

    const auto form_result = ask_form(
        PLUGIN_NAME ": Options\n"
        "<#Auto create ida pattern:R>\n" // 0
        "<#Auto create code pattern:R>\n" // 1
        "<#Auto create crc32 pattern:R>\n" // 2
        "<#Create ida pattern from selection:R>\n" // 3
        "<#Create code pattern from selection:R>\n" // 4
        "<#Create crc32 pattern from selection:R>\n" // 5
        "<#Test ida pattern:R>\n" // 6
        "<#Test code pattern:R>\n" // 7
        "<#Convert a sig:R>\n" // 8
        "<#Configure the plugin:R>>\n\n" // 9
        , &selected_action );

    if (form_result > 0)
    {
        switch (selected_action)
        {
        case 0:
            generator::generate_sig(sig::ida);
            break;
        case 1:
            generator::generate_sig(sig::code);
            break;
        case 2:
            generator::generate_sig(sig::crc);
            break;
        case 3: 
            generator::create_sig(sig::ida);
            break;
        case 4: 
            generator::create_sig(sig::code);
            break;
        case 5: 
            generator::create_sig(sig::crc);
            break;
        case 6: 
            searcher::open_ida_search();
            break;
        case 7: 
            searcher::open_code_search();
            break;
        //case 8: 
        //    ShowSigConverter( );
        //    break;
        case 9: 
            open_settings_dialog();
            break;
        default:
            break;;
        }
    }
}

void Core::open_settings_dialog()
{
    Settings settings;

    auto selection_type_var = settings.value(Settings::selection_type, 0u);
    auto max_ref_count_var = settings.value(Settings::max_ref_count, 0);
    auto keep_unsafe_data_var = settings.value(Settings::keep_unsafe_data, 1u);
    auto log_level_var = settings.value(Settings::log_level, 1u);

    ushort selection_answ = 0;
    sval_t max_ref_answ = 0;
    ushort keep_unsafe_answ = 1;
    ushort log_level_answ = 1;

    if (selection_type_var.canConvert<ushort>()) selection_answ = selection_type_var.toUInt();
    else settings.remove(Settings::selection_type);

    if (max_ref_count_var.canConvert<sval_t>()) max_ref_answ = max_ref_count_var.toLongLong();
    else settings.remove(Settings::max_ref_count);

    if (keep_unsafe_data_var.canConvert<ushort>()) keep_unsafe_answ = keep_unsafe_data_var.toUInt();
    else settings.remove(Settings::keep_unsafe_data);

    if (log_level_var.canConvert<ushort>()) log_level_answ = log_level_var.toUInt();
    else settings.remove(Settings::log_level);

    msg("[" PLUGIN_NAME "] Current Settings:\n");
    msg("-    Selection Type: %i\n", selection_answ);
    msg("-    Max Reference Count: %i\n", max_ref_answ);
    msg("-    Keep Unsafe Data: %i\n", keep_unsafe_answ);
    msg("-    Log Level: %i\n", log_level_answ);

    const auto form_result = ask_form( 
        "BUTTON YES Save\n"
        PLUGIN_NAME ": Setttings\n\n"
        "<##Auto Generation##Choose the best sig from total length:R>\n"    // 0
        "<Choose the best sig from the amount of opcodes:R>\n"              // 1
        "<Choose the best sig by the smallest amount of wildcards:R>>\n"    // 2
        
        "<Maximum refs for auto generation:D:20:10::>\n"                    // Decimal number
        
        "<##Data##Add only relilable data to sigs(choose if unsure):R>\n"   // 0
        "<Include unsafe data in sigs(may produce better results):R>>\n"    // 1

        "<##Logging##Disable logging:R>\n"                                  // 0
        "<Log results:R>\n"                                                 // 1
        "<Log errors and results:R>\n"                                      // 2
        "<Log errors, results and interim steps of all proceedures:R>>\n"   // 3
        , &selection_answ, &max_ref_answ, &keep_unsafe_answ, &log_level_answ);

    if (form_result > 0)
    {
        msg("[" PLUGIN_NAME "] Current Settings:\n");
        msg("-    Selection Type: %i\n", selection_answ);
        msg("-    Max Reference Count: %i\n", max_ref_answ);
        msg("-    Keep Unsafe Data: %i\n", keep_unsafe_answ);
        msg("-    Log Level: %i\n", log_level_answ);

        settings.setValue(Settings::selection_type, selection_answ);
        settings.setValue(Settings::max_ref_count, max_ref_answ);
        settings.setValue(Settings::keep_unsafe_data, keep_unsafe_answ);
        settings.setValue(Settings::log_level, log_level_answ);
    }
}

// ============================================================================================= //
