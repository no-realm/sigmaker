#ifndef SIGNATURE_HPP
#define SIGNATURE_HPP

#include <pro.h>

namespace sig {
    enum sig_type_t {
        direct,
        function,
        reference
    };

    enum sig_format_t {
        ida,
        code,
        crc,
    };

    struct sig_t {
        qstring sig_str;
        ea_t start_address{};
        ea_t current_address{};
        size_t num_hits{};
        size_t num_ops{};
        sig_type_t sig_type;
    };

    using vec = qvector<sig_t>;

    inline bool operator==(const sig_t& lhs, const sig_t& rhs)
    {
        if (lhs.sig_str != rhs.sig_str) return false;
        if (lhs.start_address != rhs.start_address) return false;
        if (lhs.current_address != rhs.current_address) return false;
        if (lhs.num_hits != rhs.num_hits) return false;
        if (lhs.num_ops != rhs.num_ops) return false;
        return lhs.sig_type == rhs.sig_type;
    }
}

#endif // SIGNATURE_HPP
