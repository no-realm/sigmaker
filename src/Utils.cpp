#include "Utils.hpp"

#ifdef __NT__
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

    bool
    Utils::text_to_clipboard(const char* text)
    {
        auto result = false;

        if (OpenClipboard(nullptr))
        {
            if (EmptyClipboard())
            {
                const auto data_size = (strlen(text) + 1);
                if (data_size > 1)
                {
                    const auto global_text_mem = GlobalAlloc(GMEM_MOVEABLE, data_size);
                    if (global_text_mem)
                    {
                        const auto text_mem = static_cast<char*>(GlobalLock(global_text_mem));
                        if (text_mem)
                        {
                            memmove(text_mem, text, data_size);
                            GlobalUnlock(global_text_mem);
                            result = (SetClipboardData(CF_TEXT, global_text_mem) != nullptr);
                        }
                    }
                }
            }

            // No freeing needed windows now owns our memory
            CloseClipboard();
        }

        return result;
    }

    int
    __stdcall DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
    {
        return 1;
    }
#else
    bool
    Utils::text_to_clipboard(const char* text)
    {
        return false;
    }
#endif // __NT__*/