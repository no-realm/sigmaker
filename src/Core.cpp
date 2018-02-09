#include "Core.hpp"

#include "PluginConfig.hpp"
#include "Settings.hpp"

//#include <ida.hpp>
#include <idp.hpp>

// ============================================================================================= //
// [Core]                                                                                        //
// ============================================================================================= //

void Core::initPlugin() const
{
    Settings settings;

    auto logLevelVar = settings.value(Settings::iLogLevel, 1);
    auto logLevel = 1;

    if (logLevelVar.canConvert<int>()) logLevel = logLevelVar.toInt();
    else settings.remove(Settings::iLogLevel);

    if (logLevel >= 3)
    {
        auto selectionTypeVar = settings.value(Settings::iSelectionType, 1);
        auto maxRefCountVar = settings.value(Settings::iMaxRefCount, 1);
        auto keepUnsafeDataVar = settings.value(Settings::iKeepUnsafeData, 0);

        auto selectionType = 0;
        auto maxRefCount = 0;
        auto keepUnsafeData = 0;

        if (selectionTypeVar.canConvert<int>()) selectionType = selectionTypeVar.toInt();
        else settings.remove(Settings::iSelectionType);

        if (maxRefCountVar.canConvert<int>()) maxRefCount = maxRefCountVar.toInt();
        else settings.remove(Settings::iMaxRefCount);

        if (keepUnsafeDataVar.canConvert<int>()) keepUnsafeData = keepUnsafeDataVar.toInt();
        else settings.remove(Settings::iKeepUnsafeData);

        msg("[" PLUGIN_NAME "] Current Settings:\n");
        msg("-    Selection Type: %i", selectionType);
        msg("-    Max Reference Count: %i", maxRefCount);
        msg("-    Keep Unsafe Data: %i", keepUnsafeData);
    }
}

void Core::runPlugin()
{
    openOptionsDialog();
}

void Core::openOptionsDialog()
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
        //case 0:
        //    GenerateSig( SIG_IDA );
        //    break;
        //case 1:
        //    GenerateSig( SIG_CODE );
        //    break;
        //case 2:
        //    GenerateSig( SIG_CRC );
        //    break;
        //case 3: 
        //    CreateSig( SIG_IDA );
        //    break;
        //case 4: 
        //    CreateSig( SIG_CODE );
        //    break;
        //case 5: 
        //    CreateSig( SIG_CRC );
        //    break;
        //case 6: 
        //    ShowSearchWindow( );
        //    break;
        //case 7: 
        //    ShowSearchDialog( );
        //    break;
        //case 8: 
        //    ShowSigConverter( );
        //    break;
        case 9: 
            openSettingsDialog();
            break;
        default:
            break;;
        }
    }
}

void Core::openSettingsDialog()
{
    Settings settings;
    char szBuffer[MAXSTR] = { 0 };

    auto selectionTypeVar = settings.value(Settings::iSelectionType, 1);
    auto maxRefCountVar = settings.value(Settings::iMaxRefCount, 1);
    auto keepUnsafeDataVar = settings.value(Settings::iKeepUnsafeData, 0);
    auto logLevelVar = settings.value(Settings::iLogLevel, 1);

    auto selectionType = 0;
    auto maxRefCount = 0;
    auto keepUnsafeData = 0;
    auto logLevel = 1;

    if (selectionTypeVar.canConvert<int>()) selectionType = selectionTypeVar.toInt();
    else settings.remove(Settings::iSelectionType);

    if (maxRefCountVar.canConvert<int>()) maxRefCount = maxRefCountVar.toInt();
    else settings.remove(Settings::iMaxRefCount);

    if (keepUnsafeDataVar.canConvert<int>()) keepUnsafeData = keepUnsafeDataVar.toInt();
    else settings.remove(Settings::iKeepUnsafeData);

    if (logLevelVar.canConvert<int>()) logLevel = logLevelVar.toInt();
    else settings.remove(Settings::iLogLevel);

    const int form_result = ask_form( 
        PLUGIN_NAME ": Setttings\n"
        "<#Choose the best sig from total length:R>\n" // 0
        "<#Choose the best sig from the amount of opcodes:R>\n" // 1
        "<#Choose the best sig by the smallest amount of wildcards:R>>\n" // 2
        "<Maximum refs for auto generation:A:20:10::>\n"
        "<#Add only relilable data to sigs(choose if unsure):R>\n" // 0
        "<#Include unsafe data in sigs(may produce better results):R>>\n" // 1
        "<#Disable logging:R>\n" // 0
        "<#Log results:R>\n" // 1
        "<#Log errors and results:R>\n" // 2
        "<#Log errors, results and interim steps of all proceedures:R>>\n" // 3
        , &selectionType, szBuffer, &keepUnsafeData, &logLevel );

    if (form_result > 0)
    {
        qsscanf(szBuffer, "%i", &maxRefCount); 

        settings.setValue(Settings::iSelectionType, selectionType);
        settings.setValue(Settings::iMaxRefCount, maxRefCount);
        settings.setValue(Settings::iKeepUnsafeData, keepUnsafeData);
        settings.setValue(Settings::iLogLevel, logLevel);
    }
}

// ============================================================================================= //
