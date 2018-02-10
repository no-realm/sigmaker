#include "Generator.hpp"

#include "Utils.hpp"
#include "Settings.hpp"
#include "PluginConfig.hpp"
#include "Searcher.hpp"

#include <idp.hpp>

bool
auto_generate_sig(sig::vec& sigs, ea_t address);
bool
match_operands(insn_t* cmd, uint operand, uint op_size);
uint
get_current_opcode_size(insn_t* cmd, uint& count);
void
add_whitespaces_to_sig(qstring& sig_str, ea_t sig_size);
size_t
get_char_count(const char* sig_str, char wildcard_char, bool case_insensitive = true);
uint64_t
get_address_bytes(const ea_t& address, const uint& address_size);

void
generator::create_sig(const sig::sig_format_t sig_format)
{
    qstring sig_str;
    ea_t start_address, end_address;
    Settings settings;

    auto log_level_var = settings.value(Settings::log_level, 1);
    auto log_level = 1;

    if (log_level_var.canConvert<int>()) log_level = log_level_var.toInt();
    else settings.remove(Settings::log_level);

    if (!read_range_selection(get_current_viewer(), &start_address, &end_address))
    {
        if (log_level >= 1) msg("[" PLUGIN_NAME "] No code selected!\n");
        return;
    }

    if (end_address - start_address < 5)
    {
        if (log_level > 0) msg("[" PLUGIN_NAME "] Your selection is too short!\n");
        return;
    }

    insn_t cmd;
    func_item_iterator_t func_it;
    func_it.set_range(start_address, end_address);

    for (auto current_ins = func_it.current();
         decode_insn(&cmd, current_ins) != 0;
         current_ins = func_it.current())
    {
        if (cmd.size < 5u) add_bytes_to_sig(sig_str, current_ins, cmd.size);
        else add_ins_to_sig(&cmd, sig_str);

        if (!func_it.next_not_tail())
            break;
    }

    if (log_level >= 3) msg("[" PLUGIN_NAME "] IDA Signature at " ADDR ": %s\n", start_address, sig_str.c_str());

    qstring tmp_str;
    char mask[MAXSTR];

    // TODO: Add Converter call
    switch (sig_format)
    {
    case sig::ida:
        break;
    case sig::code:
        //IDAToCode(sig_str, tmp_str, mask);
        sig_str.sprnt("%s, %s", tmp_str.c_str(), mask);
        break;
    case sig::crc:
        //IDAToCRC(sig_str, start_address, end_address);
        sig_str.sprnt("0x%X, 0x%X", start_address, end_address);
        break;
    }

    // TODO: Add clipboard call
    //TextToClipboard(sig_str.c_str());

    if (log_level >= 1)
    {
        switch (sig_format)
        {
        case sig::ida:
            msg("[" PLUGIN_NAME "] IDA Signature at " ADDR ": %s\n", start_address, sig_str.c_str());
            break;
        case sig::code:
            msg("[" PLUGIN_NAME "] CODE Signature at " ADDR ": %s\n", start_address, sig_str.c_str());
            break;
        case sig::crc:
            msg("[" PLUGIN_NAME "] CRC Signature at " ADDR ":  %s\n", start_address, sig_str.c_str());
            break;
        }
    }
}

void
generator::generate_sig(const sig::sig_format_t sig_format)
{
    sig::vec sigs;
    sig::vec::iterator sig_it = nullptr;
    size_t sig_length = 9999;
    Settings settings;

    auto log_level_var = settings.value(Settings::log_level, 1);
    auto selection_type_var = settings.value(Settings::selection_type, 0);

    auto log_level = 1;
    auto selection_type = 0;

    if (log_level_var.canConvert<int>()) log_level = log_level_var.toInt();
    else settings.remove(Settings::log_level);

    if (selection_type_var.canConvert<int>()) selection_type = selection_type_var.toInt();
    else settings.remove(Settings::selection_type);

    const auto selected_address = get_screen_ea();

    if (!IS_VALID_EA(selected_address))
    {
        if (log_level >= 2) msg("[" PLUGIN_NAME "] You must select an address!\n");
        return;
    }

    if (!auto_generate_sig(sigs, selected_address)) return;

    for (auto sig = sigs.begin(); sig != sigs.end(); ++sig)
    {
        if (selection_type == 0)
        {
            const auto str_length = sig->sig_str.length();
            if (sig_length > str_length || (sig->sig_type == sig::direct && sig_length == str_length))
            {
                sig_length = str_length;
                sig_it = sig;
            }
        }
        else if (selection_type == 1)
        {
            if (sig_length > sig->num_ops || (sig->sig_type == sig::direct && sig_length == sig->num_ops))
            {
                sig_length = sig->num_ops;
                sig_it = sig;
            }
        }
        else
        {
            const auto char_count = get_char_count(sig->sig_str.c_str(), '?');

            if (sig_length > char_count || (sig->sig_type == sig::direct && sig_length == char_count))
            {
                sig_length = char_count;
                sig_it = sig;
            }
        }
    }

    qstring sig_str = sig_it->sig_str, tmp_str;
    char mask[MAXSTR];
    ea_t start_address = 0u, end_address = 0u;

    // TODO: Add Convertion call

    switch (sig_format)
    {
    case sig::ida:
        break;
    case sig::code:
        //IDAToCode( sig_str, tmp_str, mask );
        sig_str.sprnt("%s, %s", tmp_str.c_str(), mask);
        break;
    case sig::crc:
        //IDAToCRC( sig_str, start_address, end_address );
        sig_str.sprnt("0x%X, 0x%X", start_address, end_address);
        break;
    }

    // TODO: Add clipboard call
    //TextToClipboard(sig_str.c_str());

    if (log_level >= 1)
    {
        switch (sig_it->sig_type)
        {
        case sig::direct:
            msg("[" PLUGIN_NAME "] DIRECT Signature at " ADDR ": %s\n", sig_it->start_address, sig_str.c_str());
            break;
        case sig::function:
            {
                insn_t current_insn;
                if (decode_insn(&current_insn, sig_it->start_address) != 0)
                {
                    // addr + call_op_size + call_offset + infunc_offset
                    const auto call_op_size = current_insn.size;
                    const auto addr_byte_size = (call_op_size - 1) * 8;
                    const auto call_offset = get_address_bytes(sig_it->start_address + 1, addr_byte_size);
                    const auto infunc_offset = selected_address - (sig_it->start_address + call_op_size + call_offset);

                    msg("[" PLUGIN_NAME "] FUNCTION REFERENCE Signature at " ADDR ": (op:+%x call:+%x offset:+%x) %s\n"
                        , sig_it->start_address
                        , call_op_size
                        , call_offset
                        , infunc_offset
                        , sig_str.c_str());
                }
                else
                {
                    msg("[" PLUGIN_NAME "] FUNCTION REFERENCE Signature at " ADDR ": (offset: +0x%x) %s\n", sig_it->start_address
                        , selected_address - sig_it->start_address
                        , sig_str.c_str());
                }

                break;
            }
        case sig::reference:
            {
                insn_t current_insn;
                if (decode_insn(&current_insn, sig_it->start_address) != 0)
                {
                    // addr + op_size + ref_offset
                    const auto op_size = current_insn.size;
                    const auto addr_byte_size = (op_size - 1) * 8;
                    const auto ref_offset = get_address_bytes(sig_it->start_address + 1, addr_byte_size);

                    msg("[" PLUGIN_NAME "] CODE REFERENCE Signature at " ADDR ": (op:+%x ref:+%x) %s\n", sig_it->start_address
                        , op_size
                        , ref_offset
                        , sig_str.c_str());
                }
                else
                {
                    msg("[" PLUGIN_NAME "] CODE REFERENCE Signature at " ADDR ": %s\n", sig_it->start_address, sig_str.c_str());
                }

                break;
            }
        }
    }
}

bool
generator::add_instruction(qstring& sig_str, ea_t& current_address)
{
    insn_t cmd;

    if (decode_insn(&cmd, current_address) == 0) return false;
    if (cmd.size == 0) return false;

    if (cmd.size < 5) add_bytes_to_sig(sig_str, current_address, cmd.size);
    else add_ins_to_sig(&cmd, sig_str);

    current_address += cmd.size;
    return true;
}

void
generator::add_ins_to_sig(insn_t* cmd, qstring& sig_str)
{
    auto count = 0u;
    const auto op_size = get_current_opcode_size(cmd, count);

    if (op_size == 0) return add_bytes_to_sig(sig_str, cmd->ea, cmd->size);
    add_bytes_to_sig(sig_str, cmd->ea, op_size);

    if (match_operands(cmd, 0, op_size)) add_bytes_to_sig(sig_str, cmd->ea + op_size, cmd->size - op_size);
    else add_whitespaces_to_sig(sig_str, cmd->size - op_size);
}

void
generator::add_bytes_to_sig(qstring& sig_str, const ea_t address, const ea_t byte_size)
{
    for (ea_t i = 0; i < byte_size; i++)
        sig_str.cat_sprnt("%02X ", get_byte(address + i));
}

bool
auto_generate_sig(sig::vec& sigs, const ea_t address)
{
    show_wait_box("[" PLUGIN_NAME "] Please Wait...");

    // Clear previous signatures
    sigs.clear();
    sig::vec _sigs;
    size_t total_count = 0;
    Settings settings;

    auto log_level_var = settings.value(Settings::log_level, 1);
    auto max_ref_count_var = settings.value(Settings::max_ref_count, 0u);

    auto log_level = 1;
    auto max_ref_count = 0u;

    if (log_level_var.canConvert<int>()) log_level = log_level_var.toInt();
    else settings.remove(Settings::log_level);

    if (max_ref_count_var.canConvert<uint>()) max_ref_count = max_ref_count_var.toUInt();
    else settings.remove(Settings::max_ref_count);

    // This is just a check to see whether the function is valid code
    if (get_func_num(address) != -1)
    {
        sig::sig_t target_location;
        target_location.start_address = target_location.current_address = address;
        target_location.num_ops = 0;
        target_location.sig_type = sig::direct;
        _sigs.push_back(target_location);
        total_count++;

        if (log_level >= 3) msg("[" PLUGIN_NAME "] A DIRECT signature is available for the current address at " ADDR ".\n", address);
    }

    if (log_level >= 3) msg("[" PLUGIN_NAME "] Searching for REFERENCES...\n");

    for (auto current_address = get_first_cref_to(address);
         IS_VALID_EA(current_address);
         current_address = get_next_cref_to(address, current_address))
    {
        if (current_address == address) continue;

        insn_t current_insn;
        if (decode_insn(&current_insn, current_address) != 0)
            if (current_address + current_insn.size == address)
                continue;

        sig::sig_t target_location;
        target_location.start_address = target_location.current_address = current_address;
        target_location.num_ops = 0;
        target_location.sig_type = sig::reference;
        _sigs.push_back(target_location);
        total_count++;

        if (max_ref_count > 0 && total_count >= max_ref_count) break;

        if (log_level >= 3)
            msg("[" PLUGIN_NAME "] A valid CODE REFERENCE was found for the current address at " ADDR ".\n"
                , current_address);
    }

    if (log_level >= 3 && total_count > 1) msg("[" PLUGIN_NAME "] Added %i CODE REFERENCE(s) to the selected address.\n", total_count - 1);
    //if (log_level >= 3) msg("[" PLUGIN_NAME "] Not enough candidates were found (%i so far), trying FUNCTION REFERENCE(s).\n", total_count - 1);

    const auto func_ptr = get_func(address);
    if (func_ptr && func_ptr->start_ea != address)
    {
        if (log_level >= 3) msg("[" PLUGIN_NAME "] Valid function. Searching for references...\n");

        for (auto current_address = get_first_cref_to(func_ptr->start_ea);
             IS_VALID_EA(current_address);
             current_address = get_next_cref_to(func_ptr->start_ea, current_address))
        {
            if (current_address == address) continue;

            sig::sig_t target_location;
            target_location.start_address = target_location.current_address = current_address;
            target_location.num_ops = 0;
            target_location.sig_type = sig::function;
            _sigs.push_back(target_location);
            total_count++;

            if (max_ref_count > 0 && total_count >= max_ref_count) break;

            if (log_level >= 3)
                msg("[" PLUGIN_NAME "] A valid FUNCTION REFERENCE was found for the current address at " ADDR ".\n"
                    , current_address);
        }
    }
    else if (log_level >= 2) msg("[" PLUGIN_NAME "] Invalid Function!\n");

    if (log_level >= 3) msg("[" PLUGIN_NAME "] Added a total of %i candidate(s).\n", total_count - 1);

    while (!_sigs.empty() && !searcher::has_one_hit_sig(_sigs))
    {
        for (auto& sig : _sigs)
        {
            if (!generator::add_instruction(sig.sig_str, sig.current_address))
            {
                if (log_level >= 2)
                    msg("[" PLUGIN_NAME "] Dropped signature due to decompilation failure!\n");

                _sigs.del(sig);
                total_count--;
                continue;
            }

            sig.num_ops++;
            sig.num_hits = (sig.sig_str.length() > 5) ? searcher::get_occurrence_count(sig.sig_str, true) : 0;
        }
    }

    if (_sigs.empty())
    {
        hide_wait_box();
        if (log_level > 0) msg("[" PLUGIN_NAME "] Not enough candidates to proceed. Aborting!\n");
        return false;
    }

    for (auto& sig : _sigs)
    {
        if (sig.num_hits == 1)
        {
            if (log_level >= 3)
                msg("[" PLUGIN_NAME "] Signature (%s) at " ADDR " is a viable candidate for final evaluation.\n"
                    , sig.sig_str.c_str(), sig.start_address);
            sigs.push_back(sig);
        }
    }

    hide_wait_box();
    _sigs.clear();
    return !sigs.empty();
}

bool
match_operands(insn_t* cmd, uint operand, uint op_size)
{
    // Check DATA first reference
    if (!IS_VALID_EA(get_first_dref_from(cmd->ea))) return false;

    Settings settings;
    auto keep_unsafe_data_var = settings.value(Settings::keep_unsafe_data, 1);
    auto keep_unsafe_data = 1;
    if (keep_unsafe_data_var.canConvert<int>()) keep_unsafe_data = keep_unsafe_data_var.toInt();
    else settings.remove(Settings::keep_unsafe_data);

    if (keep_unsafe_data != 0)
    {
        // Check first far code reference
        if (!IS_VALID_EA(get_first_fcref_from(cmd->ea))) return false;
    }
    else
    {
        // Check first code reference
        if (!IS_VALID_EA(get_first_cref_from(cmd->ea))) return false;
    }

    return true;
}

uint
get_current_opcode_size(insn_t* cmd, uint& count)
{
    for (auto i = 0u; i < UA_MAXOP; ++i)
    {
        count = i;
        if (cmd->ops[i].type == o_void) return 0;
        if (cmd->ops[i].offb != 0) return cmd->ops[i].offb;
    }

    return 0;
}

void
add_whitespaces_to_sig(qstring& sig_str, const ea_t sig_size)
{
    for (ea_t i = 0; i < sig_size; i++)
        sig_str.cat_sprnt("? ");
}

size_t
get_char_count(const char* sig_str, const char wildcard_char, const bool case_insensitive)
{
    if (sig_str == nullptr) return 0u;
    size_t len = 0u;

    do
    {
        if (case_insensitive) { if (qtolower(*sig_str) == qtolower(wildcard_char)) len++; }
        else { if (*sig_str == wildcard_char) len++; }
    }
    while (*sig_str++);

    return len;
}

uint64_t
get_address_bytes(const ea_t& address, const uint& address_size)
{
    uint64_t addr = 0;

    switch (address_size)
    {
    case 8:
        {
            auto ea = address;
            uint32_t v;
            auto nbit = 0;
            addr = get_8bit(&ea, &v, &nbit);
            break;
        }
    case 16:
        addr = get_16bit(address);
        break;
    case 32:
        addr = get_32bit(address);
        break;
    case 64:
        addr = get_64bit(address);
        break;
    default:
        break;
    }

    return addr;
}
