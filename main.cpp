// coded by ellii <3
#include <windows.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <algorithm>
#include <set>
#include <fstream>
#include <ctime>
#include <cctype>
#pragma comment(lib, "kernel32.lib")

const char* DUMPER_VERSION = "b51"; 
// format b = build 
// first number is the increment of the build 
// second number is the change 1 is a minor change and 2 is major


struct function_entry {
    ULONG_PTR address;
    std::string name;
};

std::string to_lower(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(), ::tolower);
    return out;
}

void print_primitive_typedefs(FILE* file) {
    fprintf(file,
        "typedef ULONG_PTR ulong_ptr_t;\n"
        "typedef unsigned __int64* qword_ptr_t;\n"
        "typedef char char_t;\n"
        "typedef int int_t;\n"
        "typedef unsigned long* dword_ptr_t;\n"
        "\n");
}

std::string get_typedef_alias(const std::string& raw) {
    if (raw == "ulong_ptr") return "ulong_ptr_t";
    if (raw == "qword*")    return "qword_ptr_t";
    if (raw == "char")      return "char_t";
    if (raw == "int")       return "int_t";
    if (raw == "dword*")    return "dword_ptr_t";
    return raw;
}

bool is_valid_start(BYTE* p) {
    if (p[0] == 0xCC || p[0] == 0xC3) return false;
    if (p[0] == 0x00 && p[1] == 0x00) return false;
    if (*(WORD*)p == 0xFFFF) return false;
    return true;
}

bool is_function_prologue(BYTE* p) {
    if (p[0] == 0x48 && p[1] == 0x89 && p[2] == 0x4C && p[3] == 0x24 && p[4] == 0x08) return true;
    if (p[0] == 0x40 && p[1] == 0x53) return true;
    if (p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xEC) return true;
    if (p[0] == 0x48 && p[1] == 0x89 && p[2] == 0x5C && p[3] == 0x24) return true;
    if (p[0] == 0x55 && p[1] == 0x48 && p[2] == 0x89 && p[3] == 0xE5) return true;
    if (p[0] == 0x48 && p[1] == 0x8B && p[2] == 0xEC) return true;
    return false;
}

std::string get_calling_convention(BYTE*) { return "__fastcall"; }

int count_parameters(BYTE* start, BYTE* end) {
    int count = 0;
    for (BYTE* p = start + 5; p < end - 8; ++p) {
        if (p[0] == 0x48 && p[1] == 0x89 && (p[2] & 0xC7) == 0x44 && p[3] == 0x24) {
            count++;
        }
        else if (p[0] == 0xC3) break;
        else if (p[0] == 0xCC) break;
        else if (p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xC4) break;
        else if (p[0] == 0x5D && p[1] == 0xC3) break;
        else if (p[0] == 0xC2) break;
    }
    return count;
}

std::string get_param_type(int index) {
    static const char* types[] = {
        "ulong_ptr", "qword*", "char", "int", "dword*", "dword*", "int",
        "float", "double", "void*", "byte", "word", "dword", "qword"
    };
    return types[index % 14];
}

BYTE* find_function_end(BYTE* start, BYTE* section_end) {
    for (BYTE* p = start + 8; p < section_end - 8; ++p) {
        if (p[0] == 0xC3) return p + 1;
        if (p[0] == 0xC2) return p + 3;
        if (p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xC4) {
            int offset = p[3];
            if (p + 4 + offset < section_end && (p[4 + offset] == 0xC3 || p[4 + offset] == 0x5D))
                return p + 4 + offset;
        }
        if (p[0] == 0x5D && p[1] == 0xC3) return p + 2;
    }
    return section_end;
}

void print_function_typedefs(ULONG_PTR addr, const std::string& orig_name, FILE* file, int param_count) {
    std::string cc = get_calling_convention((BYTE*)addr);
    std::string primary_name = orig_name + "_t";
    std::string lower_name = to_lower(orig_name) + "_t";

    char line[8192];
    int pos = 0;

    pos += sprintf_s(line + pos, sizeof(line) - pos,
        "typedef __int64 (%s *%s)(", cc.c_str(), primary_name.c_str());

    for (int i = 0; i < param_count; ++i) {
        std::string raw_type = get_param_type(i);
        std::string alias = get_typedef_alias(raw_type);
        pos += sprintf_s(line + pos, sizeof(line) - pos,
            "%s a%d", alias.c_str(), i + 1);
        if (i < param_count - 1)
            pos += sprintf_s(line + pos, sizeof(line) - pos, ", ");
    }
    pos += sprintf_s(line + pos, sizeof(line) - pos, ");\n");

    // printf("%s", line);
    if (file) fprintf(file, "%s", line);
}

std::string get_current_time() {
    std::time_t now = std::time(nullptr);
    struct tm timeinfo;
    localtime_s(&timeinfo, &now);
    char buffer[32];
    std::strftime(buffer, sizeof(buffer), "%H:%M %d/%m/%Y", &timeinfo);
    return std::string(buffer);
}

void dump_all_functions(const char* filename, FILE* file) {
    std::ifstream in(filename, std::ios::binary | std::ios::ate);
    if (!in.is_open()) { printf("error: failed to open file: %s\n", filename); return; }
    std::streamsize size = in.tellg(); in.seekg(0, std::ios::beg);
    std::vector<BYTE> buffer(size);
    if (!in.read((char*)buffer.data(), size)) { printf("error: failed to read file\n"); return; }

    BYTE* image = buffer.data();
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)image;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { printf("error: invalid dos header\n"); return; }
    if (dos->e_lfanew >= size) { printf("error: invalid pe offset\n"); return; }
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(image + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { printf("error: invalid nt header\n"); return; }
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);

    std::vector<function_entry> functions;
    std::set<ULONG_PTR> seen_addresses;

    DWORD export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (export_rva) {
        IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(image + export_rva);
        DWORD* name_rvas = (DWORD*)(image + exp->AddressOfNames);
        WORD* ordinals = (WORD*)(image + exp->AddressOfNameOrdinals);
        DWORD* func_rvas = (DWORD*)(image + exp->AddressOfFunctions);

        for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
            DWORD name_rva = name_rvas[i];
            if (name_rva >= size) continue;
            const char* name = (const char*)(image + name_rva);
            if (!name || name[0] == '\0') continue;

            DWORD func_rva = func_rvas[ordinals[i]];
            if (func_rva == 0) continue;
            if (func_rva >= export_rva && func_rva < export_rva + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
                continue;

            ULONG_PTR addr = (ULONG_PTR)image + func_rva;
            functions.push_back({ addr, std::string(name) });
            seen_addresses.insert(addr);
        }
    }

    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (!(sections[i].Characteristics & IMAGE_SCN_CNT_CODE)) continue;
        DWORD sec_rva = sections[i].VirtualAddress;
        DWORD raw_size = sections[i].SizeOfRawData;
        if (raw_size == 0) raw_size = sections[i].Misc.VirtualSize;
        if (sec_rva + raw_size > size) continue;

        BYTE* sec_start = image + sec_rva;
        BYTE* sec_end = sec_start + raw_size;

        for (BYTE* p = sec_start; p < sec_end - 64; ++p) {
            if (!is_valid_start(p) || !is_function_prologue(p)) continue;
            if (seen_addresses.count((ULONG_PTR)p)) continue;

            BYTE* func_end = find_function_end(p, sec_end);
            int param_count = count_parameters(p, func_end);

            char name[64];
            sprintf_s(name, "sub_%llx", (ULONG_PTR)p - (ULONG_PTR)image);
            functions.push_back({ (ULONG_PTR)p, name });
            seen_addresses.insert((ULONG_PTR)p);

            p = func_end - 1;
        }
    }

    std::sort(functions.begin(), functions.end(),
        [](const function_entry& a, const function_entry& b) { return a.address < b.address; });

    std::string timestamp = get_current_time();
   
    if (file) {
        fprintf(file, "/*\n"); 
        fprintf(file, "dumper version: %s\n", DUMPER_VERSION);
        fprintf(file, "dumped at: %s\n", timestamp.c_str());
        fprintf(file, "total functions: %zu\n", functions.size());
        fprintf(file, "created by ellii <3\n");
        fprintf(file, "*/\n\n"); 
    }


    print_primitive_typedefs(file);

    for (const auto& f : functions) {
        BYTE* func_start = (BYTE*)f.address;
        BYTE* func_end = find_function_end(func_start, image + size);
        int param_count = count_parameters(func_start, func_end);
        print_function_typedefs(f.address, f.name, file, param_count);
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("usage: %s <exe_or_dll> <output.txt>\n", argv[0]);
        return 1;
    }

    FILE* output_file = nullptr;
    if (fopen_s(&output_file, argv[2], "w") != 0 || !output_file) {
        printf("error: failed to open output file: %s\n", argv[2]);
        return 1;
    }

    dump_all_functions(argv[1], output_file);
    fclose(output_file);

    printf("\ndone! output written to %s\n", argv[2]);
    return 0;
}