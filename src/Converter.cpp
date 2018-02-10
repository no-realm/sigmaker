#include "Converter.hpp"

#include "Utils.hpp"
#include "PluginConfig.hpp"
#include "Settings.hpp"

#include <idp.hpp>

bool
get_next_byte(char** str, unsigned char& byte_val, bool& is_wcard);
int
text_to_hex(const char* str, unsigned char* byte_array, char* mask = nullptr);


void
converter::ida_to_code(const qstring& sig_string, qstring& byte_sig_str, char* mask)
{
    unsigned char byte_array[MAXSTR];
    const auto count = text_to_hex(sig_string.c_str(), byte_array, mask);
    byte_sig_str.clear();

    for (auto i = 0; i < count; i++)
        byte_sig_str.cat_sprnt("\\x%02X", byte_array[i]);
}

void
converter::ida_to_crc(const qstring& sig_str, ea_t& crc32_ea, ea_t& mask_ea)
{
    unsigned char byte_array[MAXSTR];
    char mask[MAXSTR];
    const auto count = text_to_hex(sig_str.c_str(), byte_array, mask);

    for (auto i = 0; i < 32; i++)
    {
        if (i <= count && mask[i] == 'x')
        {
            mask_ea |= 1ull << i;
        }
        else
        {
            mask_ea &= ~(1ull << i);
        }
    }

    crc32_ea = calc_crc32(0, byte_array, 32);
}

void
converter::code_to_crc(const qstring& byte_sig_str, const qstring& mask_str, ea_t& crc32_ea, ea_t& mask_ea)
{
    unsigned char byte_array[MAXSTR];
    char mask[MAXSTR];
    const auto count = text_to_hex(byte_sig_str.c_str(), byte_array, mask);

    for (auto i = 0; i < 32; i++)
    {
        if (i <= count && mask[i] == 'x')
        {
            mask_ea |= 1ull << i;
        }
        else
        {
            mask_ea &= ~(1ull << i);
        }
    }

    crc32_ea = calc_crc32(0, byte_array, 32);
}

void
converter::code_to_ida(qstring& sig_str, const qstring& byte_sig_str, const qstring& mask_str)
{
    unsigned char byte_array[MAXSTR] = {0};

    text_to_hex(byte_sig_str.c_str(), byte_array);

    const auto mask_length = mask_str.length();
    sig_str.clear();

    for (size_t i = 0; i < mask_length; i++)
    {
        if (mask_str[i] == 'x' || mask_str[i] == 'X')
        {
            sig_str.cat_sprnt("0x%02X ", byte_array[i]);
        }
        else
        {
            sig_str += "? ";
        }
    }
}

void
converter::code_to_idac(qstring& sig_str, const char* byte_sig_str, const char* mask)
{
    unsigned char byte_array[MAXSTR] = {0};

    text_to_hex(byte_sig_str, byte_array);

    const auto mask_length = ::qstrlen(mask);
    sig_str.clear();

    for (size_t i = 0; i < mask_length; i++)
    {
        if (mask[i] == 'x' || mask[i] == 'X')
        {
            sig_str.cat_sprnt("%02X ", byte_array[i]);
        }
        else
        {
            sig_str += "? ";
        }
    }
}

void
converter::open_sig_converter()
{
    static const char form_str[] =
        "BUTTON YES Convert\n"
        PLUGIN_NAME ": Signature Converter\n"
        "\n"
        "\n"
        "  <Sig:A5::100::>\n"
        "  <Mask:A6::100::>\n"
        "\n"
        "  <##Conversion Options##IDA to Code:R>\n" // 0
        "  <IDA to CRC:R>\n" // 1
        "  <Code to IDA:R>\n" // 2
        "  <Code to CRC:R>\n" // 3
        "  <IDA to Olly:R>\n" // 4
        "  <Olly to IDA:R>>\n" // 5
        "\n"
        "\n";

    char sig_in[MAXSTR] = {0};
    char mask_in[MAXSTR] = {0};

    ushort user_selection = 0;

    if (ask_form(form_str, sig_in, mask_in, &user_selection) > 0)
    {
        qstring tmp_str = sig_in;
        qstring sig_in_str = sig_in;
        const qstring mask_in_str = mask_in;
        ea_t crc32_ea = 0, mask_ea = 0;

        switch (user_selection)
        {
        case 0:
            ida_to_code(tmp_str, sig_in_str, mask_in);
            tmp_str.sprnt("%s, %s", sig_in, mask_in);
            break;
        case 1:
            ida_to_crc(sig_in_str, crc32_ea, mask_ea);
            tmp_str.sprnt("0x%x, 0x%x", crc32_ea, mask_ea);
            break;
        case 2:
            code_to_ida(tmp_str, sig_in_str, mask_in_str);
            break;
        case 3:
            code_to_crc(sig_in_str, mask_in_str, crc32_ea, mask_ea);
            tmp_str.sprnt("0x%x, 0x%x", crc32_ea, mask_ea);
            break;
        case 4:
            tmp_str.replace(" ? ", " ?? ");
            break;
        case 5:
            tmp_str.replace(" ?? ", " ? ");
            break;
        default: break;
        }

        // Copy to clipboard
        Utils::text_to_clipboard(tmp_str.c_str());

        Settings settings;

        auto log_level_var = settings.value(Settings::log_level, 2u);
        ushort log_level = 2u;

        if (log_level_var.canConvert<ushort>()) log_level = log_level_var.toUInt();
        else settings.remove(Settings::log_level);

        if (log_level >= 1) msg("[" PLUGIN_NAME "] Converted Signature: %s\n", tmp_str.c_str());
    }
}

bool
get_next_byte(char** str, unsigned char& byte_val, bool& is_wcard)
{
    do
    {
        if (**str == '?')
        {
            byte_val = 0;
            is_wcard = true;
            (*str)++;

            if (**str == '?')
                (*str)++;

            return true;
        }

        if (qisxdigit(**str))
        {
            is_wcard = false;
            byte_val = static_cast<unsigned char>(strtoul(*str, str, 16) & 0xFF);
            return true;
        }
    }
    while (*(*str)++);

    return false;
}

int
text_to_hex(const char* str, unsigned char* byte_array, char* mask)
{
    auto count = 0;
    auto is_wcard = false;

    if (mask)
        *mask = 0;

    if (get_next_byte(const_cast<char**>(&str), byte_array[count], is_wcard))
    {
        do
        {
            count++;

            if (mask)
                qstrncat(mask, (is_wcard) ? "?" : "x", MAXSTR);
        }
        while (get_next_byte(const_cast<char**>(&str), byte_array[count], is_wcard));
    }

    return count;
}
