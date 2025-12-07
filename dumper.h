#pragma once
#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>
#include <vector>
#include <set>
#include <string>
#include <fstream>
#include <algorithm>
#include <filesystem>
#include <ctime>
#include <cctype>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "kernel32.lib")

namespace dumper {

    const char* VERSION = "b51";

    struct functioninfo {
        ULONG_PTR addr;
        std::string name;
        int param_count;
        std::vector<BYTE> code;
        std::string signature;
    };

    struct stringinfo {
        std::string str;
        ULONG_PTR addr;
    };

    namespace util {
        std::string lower(const std::string& s) {
            std::string output = s;
            std::transform(output.begin(), output.end(), output.begin(), ::tolower);
            return output;
        }

        std::string timestamp() {
            std::time_t now = std::time(nullptr);
            char buf[32];
            struct tm t;
            localtime_s(&t, &now);
            strftime(buf, sizeof(buf), "%H:%M %d/%m/%Y", &t);
            return buf;
        }
        const char* alias(const char* type) {
            if (!strcmp(type, "ulong_ptr")) return "ulong_ptr_t";
            if (!strcmp(type, "qword*")) return "qword_ptr_t";
            if (!strcmp(type, "char")) return "char_t";
            if (!strcmp(type, "int")) return "int_t";
            if (!strcmp(type, "dword*")) return "dword_ptr_t";
            return type;
        }
        const char* param_type(int i) {
            static const char* types[] = {
                "ulong_ptr", "qword*", "char", "int", "dword*", "dword*", "int",
                "float", "double", "void*", "byte", "word", "dword", "qword"
            };
            return types[i % 14];
        }
        std::string demangle(const std::string& name) {
            char buf[1024] = {};
            if (UnDecorateSymbolName(name.c_str(), buf, sizeof(buf),
                UNDNAME_COMPLETE | UNDNAME_NO_THISTYPE)) {
                return std::string(buf);
            }
            return name;
        }
        bool valid_start(BYTE* p) {
            if (p[0] == 0xCC || p[0] == 0xC3) return false;
            if (p[0] == 0 && p[1] == 0) return false;
            if (*(WORD*)p == 0xFFFF) return false;
            return true;
        }
        bool is_prologue(BYTE* p) {
            return (p[0] == 0x48 && p[1] == 0x89) ||
                (p[0] == 0x40 && p[1] == 0x53) ||
                (p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xEC) ||
                (p[0] == 0x55 && p[1] == 0x48);
        }

        std::string generate_signature(const std::vector<BYTE>& code, size_t len = 16) {
            std::string sig;
            size_t limit = (((len) < (code.size())) ? (len) : (code.size())); // yes my compiler is aids yes i did expand this inline <3 yw
            for (size_t i = 0; i < limit; ++i) {
                char buf[4];
                sprintf_s(buf, "%02X", code[i]);
                sig += buf;
                if (i != limit - 1) sig += " ";
            }
            if (code.size() > len) sig += " ...";
            return sig;
        }
    }
    bool load_pe(const char* filename, std::vector<BYTE>& data,
        BYTE*& img, IMAGE_NT_HEADERS*& nt, IMAGE_SECTION_HEADER*& sections) {
        std::ifstream f(filename, std::ios::binary | std::ios::ate);
        if (!f.is_open()) return false;

        size_t sz = f.tellg();
        data.resize(sz);
        f.seekg(0);
        f.read((char*)data.data(), sz);

        img = data.data();
        auto dos = (IMAGE_DOS_HEADER*)img;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

        nt = (IMAGE_NT_HEADERS*)(img + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

        sections = IMAGE_FIRST_SECTION(nt);
        return true;
    }
    std::string get_architecture(IMAGE_NT_HEADERS* nt) {
        switch (nt->FileHeader.Machine) {
        case IMAGE_FILE_MACHINE_I386: return "x86";
        case IMAGE_FILE_MACHINE_AMD64: return "x64";
        case IMAGE_FILE_MACHINE_ARM64: return "ARM64";
        default: return "unknown";
        }
    }
    std::string get_compiler(IMAGE_NT_HEADERS* nt, IMAGE_SECTION_HEADER* sections) {
        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            auto& s = sections[i];
            std::string name((char*)s.Name, 8);
            if (name.find(".pdata") != std::string::npos ||
                name.find(".rdata") != std::string::npos)
                return "MSVC";
        }
        return "Unknown";
    }
    BYTE* find_end(BYTE* start, BYTE* end) {
        for (BYTE* p = start + 8; p < end - 8; p++) {
            if (p[0] == 0xC3) return p + 1; // ret
            if (p[0] == 0xC2) return p + 3; // ret imm16
            if (p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xC4) {
                int offset = p[3];
                if (p + 4 + offset < end && (p[4 + offset] == 0xC3))
                    return p + 4 + offset;
            }
        }
        return end;
    }
    int count_params(BYTE* start, BYTE* end) {
        int count = 0;
        for (BYTE* p = start + 5; p < end - 8; p++) {
            if (p[0] == 0x48 && p[1] == 0x89 && (p[2] & 0xC7) == 0x44)
                count++;
            else if (p[0] == 0xC3 || p[0] == 0xCC)
                break;
        }
        return count;
    }
    void scan_exports(std::vector<BYTE>& data, BYTE* img, IMAGE_NT_HEADERS* nt,
        std::vector<functioninfo>& funcs, std::set<ULONG_PTR>& seen) {
        DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!rva) return;

        auto exp = (IMAGE_EXPORT_DIRECTORY*)(img + rva);
        DWORD* names = (DWORD*)(img + exp->AddressOfNames);
        WORD* ords = (WORD*)(img + exp->AddressOfNameOrdinals);
        DWORD* funcs_rva = (DWORD*)(img + exp->AddressOfFunctions);

        for (DWORD i = 0; i < exp->NumberOfNames; i++) {
            const char* name = (char*)(img + names[i]);
            DWORD frva = funcs_rva[ords[i]];
            ULONG_PTR addr = (ULONG_PTR)img + frva;

            functioninfo fn;
            fn.addr = addr;
            fn.name = util::demangle(name);
            fn.param_count = 0;
            fn.signature = "";
            funcs.push_back(fn);
            seen.insert(addr);
        }
    }
    void scan_code(BYTE* img, IMAGE_NT_HEADERS* nt, IMAGE_SECTION_HEADER* sections,
        std::vector<functioninfo>& funcs, std::set<ULONG_PTR>& seen) {
        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            auto& s = sections[i];
            if (!(s.Characteristics & IMAGE_SCN_CNT_CODE)) continue;

            BYTE* st = img + s.VirtualAddress;
            BYTE* ed = st + s.SizeOfRawData;

            for (BYTE* p = st; p < ed - 64; p++) {
                if (!util::valid_start(p) || !util::is_prologue(p)) continue;
                if (seen.count((ULONG_PTR)p)) continue;

                BYTE* end = find_end(p, ed);
                int params = count_params(p, end);

                std::vector<BYTE> code(p, end);
                char name[64];
                sprintf_s(name, "sub_%llx", (ULONG_PTR)p - (ULONG_PTR)img);

                functioninfo fn;
                fn.addr = (ULONG_PTR)p;
                fn.name = name;
                fn.param_count = params;
                fn.code = code;
                fn.signature = util::generate_signature(code);

                funcs.push_back(fn);
                seen.insert((ULONG_PTR)p);

                p = end - 1;
            }
        }
    }
    void scan_strings(BYTE* img, IMAGE_NT_HEADERS* nt, IMAGE_SECTION_HEADER* sections,
        std::vector<stringinfo>& strings, int min_len = 4) {
        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            BYTE* st = img + sections[i].VirtualAddress;
            BYTE* ed = st + sections[i].SizeOfRawData;

            for (BYTE* p = st; p < ed; p++) {
                if (!isprint(*p)) continue;

                char buf[1024];
                int len = 0;
                BYTE* start = p;

                while (p < ed && isprint(*p) && len < 1024) {
                    buf[len++] = *p;
                    p++;
                }

                if (len >= min_len) {
                    buf[len] = 0;
                    strings.push_back({ buf, (ULONG_PTR)start });
                }
            }
        }
    }
    void dump_typedefs(const std::string& folder, const std::vector<functioninfo>& funcs) {
        FILE* f;
        fopen_s(&f, (folder + "/typedefs.h").c_str(), "w");

        fprintf(f, "typedef ULONG_PTR ulong_ptr_t;\n");
        fprintf(f, "typedef unsigned __int64* qword_ptr_t;\n");
        fprintf(f, "typedef char char_t;\n");
        fprintf(f, "typedef int int_t;\n");
        fprintf(f, "typedef unsigned long* dword_ptr_t;\n\n");

        for (auto& fn : funcs) {
            fprintf(f, "typedef __int64 (__fastcall *%s_t)(", fn.name.c_str());
            for (int i = 0; i < fn.param_count; i++) {
                const char* t = util::alias(util::param_type(i));
                fprintf(f, "%s a%d%s", t, i + 1, (i + 1 < fn.param_count ? ", " : ""));
            }
            fprintf(f, ");\n");
        }
        fclose(f);
    }
    void dump_decompiled(const std::string& folder, const std::vector<functioninfo>& funcs) {
        FILE* f;
        fopen_s(&f, (folder + "/decompiled.h").c_str(), "w");

        for (auto& fn : funcs) {
            fprintf(f, "// function: %s (0x%llx) params: %d\n", fn.name.c_str(), fn.addr, fn.param_count);
            fprintf(f, "// signature: %s\n", fn.signature.c_str());
            fprintf(f, "__int64 __fastcall %s(", fn.name.c_str());

            for (int i = 0; i < fn.param_count; i++)
                fprintf(f, "%s a%d%s", util::alias(util::param_type(i)), i + 1, (i + 1 < fn.param_count ? ", " : ""));

            fprintf(f, ") {\n    // raw bytes: ");
            for (auto b : fn.code) fprintf(f, "%02X ", b);
            fprintf(f, "\n}\n\n");
        }
        fclose(f);
    }

    // Dump strings
    void dump_strings(const std::string& folder, const std::vector<stringinfo>& strings) {
        FILE* f;
        fopen_s(&f, (folder + "/strings.h").c_str(), "w");

        fprintf(f, "const char* strings[] = {\n");
        for (auto& s : strings) fprintf(f, "    \"%s\",\n", s.str.c_str());
        fprintf(f, "};\n");

        fclose(f);
    }
    void dump_metadata(const std::string& folder, IMAGE_NT_HEADERS* nt,
        const std::vector<functioninfo>& funcs,
        const std::vector<stringinfo>& strings,
        const std::string& compiler = "MSVC") {
        FILE* f;
        fopen_s(&f, (folder + "/metadata.txt").c_str(), "w");

        fprintf(f, "dumper Version: %s\n", VERSION);
        fprintf(f, "dumped At: %s\n", util::timestamp().c_str());
        fprintf(f, "pe architecture: %s\n", get_architecture(nt).c_str());
        fprintf(f, "compiler: %s\n", compiler.c_str());
        fprintf(f, "total functions: %zu\n", funcs.size());
        fprintf(f, "total strings: %zu\n", strings.size());

        fclose(f);
    }
    void dump_ida(const std::string& folder, const std::vector<functioninfo>& funcs) {
        FILE* f;
        fopen_s(&f, (folder + "/ida.idc").c_str(), "w");

        fprintf(f, "// IDA IDC script generated by ellii dumper\n");
        for (auto& fn : funcs) {
            fprintf(f, "MakeName(0x%llx,\"%s\"); MakeFunction(0x%llx);\n", fn.addr, fn.name.c_str(), fn.addr);
        }

        fclose(f);
    }

}
