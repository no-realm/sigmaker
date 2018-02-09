#ifndef SETTINGS_HPP
#define SETTINGS_HPP

#include <QString>
#include <QSettings>

// ============================================================================================= //
// [Settings]                                                                                    //
// ============================================================================================= //

class Settings : public QSettings
{
public:
    Settings();
    virtual ~Settings() = default;

    // Constants.
    static const QString iSelectionType;
    static const QString iMaxRefCount;
    static const QString iKeepUnsafeData;
    static const QString iLogLevel;
};

// ============================================================================================= //

#endif
