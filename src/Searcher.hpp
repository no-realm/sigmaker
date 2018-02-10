#ifndef SEARCHER_HPP
#define SEARCHER_HPP

#include "Signature.hpp"

namespace searcher {
    void
    open_ida_search();

    void
    open_code_search();
    
    void
    open_code_search(const char* sig_str, const char* mask);
    
    bool
    has_one_hit_sig(sig::vec& sigs);
    
    size_t
    get_occurrence_count(const qstring& sig_str, bool skip_out = true);
    
    void
    search_for_sig(const qstring& sig_str);
}

#endif // SEARCHER_HPP
