#ifndef GENERATOR_HPP
#define GENERATOR_HPP

#include "Signature.hpp"

#include <idp.hpp>

namespace generator {
    void
    create_sig(sig::sig_format_t sig_format);

    void
    generate_sig(sig::sig_format_t sig_format);

    bool
    add_instruction(qstring& sig_str, ea_t& current_address);

    void
    add_ins_to_sig(insn_t* cmd, qstring& sig_str);

    void
    add_bytes_to_sig(qstring& sig_str, ea_t address, ea_t byte_size);
};

#endif // GENERATOR_HPP
