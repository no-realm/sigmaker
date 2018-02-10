#ifndef CORE_HPP
#define CORE_HPP

#include "Utils.hpp"

#include <QObject>

// ============================================================================================= //
// [Core]                                                                                        //
// ============================================================================================= //

/**
 * @brief   Plugin core singleton.
 */
class Core 
    : public QObject
    , public Utils::Singleton<Core>
{
    Q_OBJECT

public:
    /**
     * @brief   Default constructor.
     */
    Core() = default;
    /**
     * @brief   Destructor.
     */
    ~Core() = default;
    /**
     * @brief   Initialises the plugin.
     */
    static void init_plugin();
    /**
     * @brief   Runs the plugin.
     */
    static void run_plugin();
protected:
    /**
     * @brief   Opens the options dialog.
     */
    static void open_options_dialog();

    /**
     * \brief   Opens the settings dialog.
     */
    static void open_settings_dialog();
};

// ============================================================================================= //

#endif
