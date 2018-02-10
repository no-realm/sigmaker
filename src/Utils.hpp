#ifndef UTILS_HPP
#define UTILS_HPP

namespace Utils
{

// ============================================================================================= //
// sigmaker related functions                                                                    //
// ============================================================================================= //

    /**
     * \brief Checks for valid address.
     * \param x address to be checked.
     */
    #define IS_VALID_EA( x ) (x != 0 && x != BADADDR)

    #ifdef __EA64__
        #define ADDR "[ 1%X ]"
    #else
        #define ADDR "[ %X ]"
    #endif

// ============================================================================================= //
// [NonCopyable]                                                                                 //
// ============================================================================================= //

/**
 * @brief Makes derived classes non-copyable.
 */
class NonCopyable
{
    NonCopyable(const NonCopyable&); // not implemented
    NonCopyable& operator = (const NonCopyable&); // not implemented
public:
    NonCopyable() {}
    virtual ~NonCopyable() {}
};

// ============================================================================================= //
// [NonInstantiable]                                                                             //
// ============================================================================================= //

/**
 * @brief Makes derived classes non-instantiable.
 * A class inheriting from this class can only be instantiated by itself
 * or deriving classes.
 */
class NonInstantiable
{
protected:
    NonInstantiable() {}
};

// ============================================================================================= //
// [Singleton]                                                                                   //
// ============================================================================================= //

template<typename T>
class Singleton : public NonCopyable
{
    static T *m_instance;
protected:
    Singleton() {}
    virtual ~Singleton() {}
public:
    static T& instance();
    static void freeInstance();
    static bool isInstantiated();
};

// ============================================================================================= //
// Implementation of inline methods [Singleton]                                                  //
// ============================================================================================= //

template<typename T> T *Singleton<T>::m_instance = nullptr;

template<typename T> inline
T& Singleton<T>::instance()
{
    if (!m_instance)
        m_instance = new T;
    return *m_instance;
}

template<typename T> inline
void Singleton<T>::freeInstance()
{
    if (m_instance)
    {
        delete m_instance;
        m_instance = nullptr;
    }
}

template<typename T> inline
bool Singleton<T>::isInstantiated()
{
    return m_instance != nullptr;
}

// ============================================================================================= //

}

#endif
