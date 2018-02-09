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
    void initPlugin() const;
    /**
     * @brief   Runs the plugin.
     */
    void runPlugin();
protected:
    /**
     * @brief   Opens the options dialog.
     */
    void openOptionsDialog();

    /**
     * \brief   Opens the settings dialog.
     */
    static void openSettingsDialog();
};

// ============================================================================================= //

#endif
