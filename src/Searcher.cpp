#include "Searcher.hpp"

#include "Utils.hpp"
#include "PluginConfig.hpp"
#include "Settings.hpp"
#include "Generator.hpp"
#include "Converter.hpp"

#include <search.hpp>

void
searcher::open_ida_search()
{
    static const char form_str[] =
        "BUTTON YES Test\n"
        PLUGIN_NAME ": Signature Tester\n"
        "\n"
        "\n"
        "  <Signature:A5::100::>\n"
        "\n";

    qstring sig_str;
    ea_t start_address, end_address;

    if (read_range_selection(get_current_viewer(), &start_address, &end_address))
    {
        if (end_address - start_address > 5)
        {
            insn_t cmd;

            func_item_iterator_t func_it;
            func_it.set_range(start_address, end_address);

            for (auto current_ins = func_it.current();
                 decode_insn(&cmd, current_ins) != 0;
                 current_ins = func_it.current())
            {
                if (cmd.size < 5) generator::add_bytes_to_sig(sig_str, current_ins, cmd.size);
                else generator::add_ins_to_sig(&cmd, sig_str);

                if (!func_it.next_not_tail()) break;
            }
        }
    }

    char signature[MAXSTR] = {0};

    if (sig_str.length() > 3)
        qstrncpy(signature, sig_str.c_str(), sizeof(signature));

    if (ask_form(form_str, signature) > 0)
    {
        show_wait_box("[" PLUGIN_NAME "] Please wait...");
        const qstring _sig = signature;
        search_for_sig(_sig);
        hide_wait_box();
    }
}

void
searcher::open_code_search()
{
    char signature[MAXSTR] = {0}, mask[MAXSTR] = {0};

    qstring sig_str, sig_code_str;
    ea_t start_address, end_address;

    if (read_range_selection(get_current_viewer(), &start_address, &end_address))
    {
        if (end_address - start_address > 5)
        {
            insn_t cmd;

            func_item_iterator_t func_it;
            func_it.set_range(start_address, end_address);

            for (auto current_ins = func_it.current();
                 decode_insn(&cmd, current_ins) != 0;
                 current_ins = func_it.current())
            {
                if (cmd.size < 5) generator::add_bytes_to_sig(sig_str, current_ins, cmd.size);
                else generator::add_ins_to_sig(&cmd, sig_str);

                if (!func_it.next_not_tail()) break;
            }
        }
    }

    if (sig_str.length() < 3)
        return;

    converter::ida_to_code(sig_str, sig_code_str, mask);
    qstrncpy(signature, sig_code_str.c_str(), sizeof(signature));
    open_code_search(signature, mask);
}

void
searcher::open_code_search(const char* sig_str, const char* mask_str)
{
    static const char form_str[] =
        "BUTTON YES Test\n"
        PLUGIN_NAME ": Signature Tester\n"
        "\n"
        "\n"
        "  <Signature:A5::100::>\n"
        "  <Mask:A6::100::>\n"
        "\n";

    char signature[MAXSTR] = {0}, mask[MAXSTR] = {0};
    qstring _sig_str = "";

    if (sig_str)
        qstrncpy(signature, sig_str, sizeof(signature));

    if (mask_str)
        qstrncpy(mask, mask_str, sizeof(mask));

    if (ask_form(form_str, signature, mask) > 0)
    {
        show_wait_box("[" PLUGIN_NAME "] Please wait...");

        Settings settings;

        auto log_level_var = settings.value(Settings::log_level, 2u);
        ushort log_level = 2u;

        if (log_level_var.canConvert<ushort>()) log_level = log_level_var.toUInt();
        else settings.remove(Settings::log_level);

        //msg("%s %s\n", signature, mask);

        converter::code_to_idac(_sig_str, signature, mask);

        if (log_level >= 3)
            msg("%s = %s %s\n", _sig_str.c_str(), signature, mask);

        search_for_sig(_sig_str);
        hide_wait_box();
    }
}

bool
searcher::has_one_hit_sig(sig::vec& sigs)
{
    for (auto& sig : sigs)
        if (sig.num_hits == 1)
            return true;

    return false;
}

size_t
searcher::get_occurrence_count(const qstring& sig_str, const bool skip_out)
{
    size_t count = 0u;
    Settings settings;

    auto log_level_var = settings.value(Settings::log_level, 2u);
    ushort log_level = 2u;

    if (log_level_var.canConvert<ushort>()) log_level = log_level_var.toUInt();
    else settings.remove(Settings::log_level);

    auto current_address = find_binary(inf.min_ea, inf.max_ea, sig_str.c_str(), 16, SEARCH_DOWN);

    if (IS_VALID_EA(current_address))
    {
        do
        {
            count++;
            if (log_level >= 3) msg("[" PLUGIN_NAME "] Signature (found at " ADDR "): %s\n", current_address, sig_str.c_str());

            if (skip_out && count >= 2)
            {
                if (log_level >= 3) msg("[" PLUGIN_NAME "] Discarding Signature: %s\n", sig_str.c_str());
                return count;
            }

            current_address = find_binary(current_address + 1, inf.max_ea, sig_str.c_str(), 16, SEARCH_DOWN);
        }
        while (IS_VALID_EA(current_address));
    }
    else
    {
        current_address = find_binary(inf.omin_ea, inf.omax_ea, sig_str.c_str(), 16, SEARCH_DOWN);
        if (IS_VALID_EA(current_address))
        {
            do
            {
                count++;
                if (log_level >= 3) msg("[" PLUGIN_NAME "] Signature (found at " ADDR "): %s\n", current_address, sig_str.c_str());

                if (skip_out && count >= 2)
                {
                    if (log_level >= 3) msg("[" PLUGIN_NAME "] Discarding Signature: %s\n", sig_str.c_str());
                    return count;
                }

                current_address = find_binary(current_address + 1, inf.omax_ea, sig_str.c_str(), 16, SEARCH_DOWN);
            }
            while (IS_VALID_EA(current_address));
        }
    }

    return count;
}

void
searcher::search_for_sig(const qstring& sig_str)
{
    Settings settings;

    auto log_level_var = settings.value(Settings::log_level, 2u);
    ushort log_level = 2u;

    if (log_level_var.canConvert<ushort>()) log_level = log_level_var.toUInt();
    else settings.remove(Settings::log_level);

    auto current_address = find_binary(inf.min_ea, inf.max_ea, sig_str.c_str(), 16, SEARCH_DOWN);

    static const qstring separator_str = "===========================\n";
    msg(separator_str.c_str());

    if (IS_VALID_EA(current_address))
    {
        do
        {
            if (log_level > 0) msg("[" PLUGIN_NAME "] Signature found at " ADDR "\n", current_address);
            current_address = find_binary(current_address + 1, inf.max_ea, sig_str.c_str(), 16, SEARCH_DOWN);
        }
        while (IS_VALID_EA(current_address));
    }
    else
    {
        current_address = find_binary(inf.omin_ea, inf.omax_ea, sig_str.c_str(), 16, SEARCH_DOWN);

        if (IS_VALID_EA(current_address))
        {
            do
            {
                if (log_level > 0) msg("[" PLUGIN_NAME "] Signature found at " ADDR "\n", current_address);
                current_address = find_binary(current_address + 1, inf.omax_ea, sig_str.c_str(), 16, SEARCH_DOWN);
            }
            while (IS_VALID_EA(current_address));
        }
    }

    msg(separator_str.c_str());
}
