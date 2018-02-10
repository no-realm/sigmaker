#ifndef SETTINGS_HPP
#define SETTINGS_HPP

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
    static const QString selection_type;
    static const QString max_ref_count;
    static const QString keep_unsafe_data;
    static const QString log_level;
};

// ============================================================================================= //

#endif
