// created by ellii
#include "dumper.h"

int main(int argc, char* argv[]) {
    if (argc < 2) { 
        printf("Usage: %s <exe_or_dll>\n", argv[0]); 
        return 1;
    }
    std::string folder = std::string(argv[1]) + "_dump"; 
    std::filesystem::create_directories(folder);
    std::vector<BYTE> data;
    BYTE* img = nullptr;
    IMAGE_NT_HEADERS* nt = nullptr; 
    IMAGE_SECTION_HEADER* sections = nullptr;

    if (!dumper::load_pe(argv[1], data, img, nt, sections)) 
    { 
        printf("Failed to load PE\n"); 
        return 1; 
    }

    std::vector<dumper::functioninfo> funcs;
    std::set<ULONG_PTR> seen; 

    dumper::scan_exports(data, img, nt, funcs, seen);
    dumper::scan_code(img, nt, sections, funcs, seen);

    std::vector<dumper::stringinfo> strings;

    dumper::scan_strings(img, nt, sections, strings);
    dumper::dump_typedefs(folder, funcs); 
    dumper::dump_decompiled(folder, funcs);
    dumper::dump_strings(folder, strings);

    dumper::dump_metadata(folder, nt, funcs, strings, dumper::get_compiler(nt, sections));
    dumper::dump_ida(folder, funcs);

    printf("Dump complete in folder: %s\n", folder.c_str());
    return 0;
}
