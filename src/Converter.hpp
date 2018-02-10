#ifndef CONVERTER_HPP
#define CONVERTER_HPP

#include <ida.hpp>

namespace converter {
    void
    ida_to_code(const qstring& sig_string, qstring& byte_sig_str, char* mask);
    
    void
    ida_to_crc(const qstring& sig_str, ea_t& crc32_ea, ea_t& mask_ea);
    
    void
    code_to_crc(const qstring& byte_sig_str, const qstring& mask_str, ea_t& crc32_ea, ea_t& mask_ea);
    
    void
    code_to_ida(qstring& sig_str, const qstring& byte_sig_str, const qstring& mask_str);

    void
    code_to_idac(qstring& sig_str, const char* byte_sig_str, const char* mask);
    
    void
    open_sig_converter();
}

#endif // CONVERTER_HPP
