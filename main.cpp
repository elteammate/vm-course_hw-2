#include <algorithm>
#include <chrono>
#include <memory>
#include <numeric>
#include <vector>
#include <bitset>
#include <cstring>
#include <unordered_map>

extern "C" {
#include <runtime.h>
#include <gc.h>
void *__stop_custom_data;
void *__start_custom_data;
}


using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;
using usize = uintptr_t;
using i8 = int8_t;
using i16 = int16_t;
using i32 = int32_t;
using i64 = int64_t;
using isize = std::ptrdiff_t;
using f32 = float;
using f64 = double;


#define kase break; case
#define otherwise break; default
#define CONCAT(a, b) a ## b


template <typename T>
std::unique_ptr<T []> pin_array(std::vector<T> vec) {
    std::unique_ptr<T[]> ptr(new T[vec.size()]);
    std::move(vec.begin(), vec.end(), ptr.get());
    return std::move(ptr);
}


namespace el {
    enum class Op : u8 {
        BINOP_ADD = 0x01,
        BINOP_SUB = 0x02,
        BINOP_MUL = 0x03,
        BINOP_DIV = 0x04,
        BINOP_REM = 0x05,
        BINOP_LT = 0x06,
        BINOP_LE = 0x07,
        BINOP_GT = 0x08,
        BINOP_GE = 0x09,
        BINOP_EQ = 0x0a,
        BINOP_NE = 0x0b,
        BINOP_AND = 0x0c,
        BINOP_OR = 0x0d,

        CONST = 0x10,
        STRING = 0x11,
        SEXP = 0x12,
        STI = 0x13,
        STA = 0x14,
        JMP = 0x15,
        END = 0x16,
        RET = 0x17,
        DROP = 0x18,
        DUP = 0x19,
        SWAP = 0x1a,
        ELEM = 0x1b,

        LD_GLOBAL = 0x20,
        LD_LOCAL = 0x21,
        LD_ARG = 0x22,
        LD_CLOSURE = 0x23,
        LDA_GLOBAL = 0x30,
        LDA_LOCAL = 0x31,
        LDA_ARG = 0x32,
        LDA_CLOSURE = 0x33,
        ST_GLOBAL = 0x40,
        ST_LOCAL = 0x41,
        ST_ARG = 0x42,
        ST_CLOSURE = 0x43,

        CJMPZ = 0x50,
        CJMPNZ = 0x51,
        BEGIN = 0x52,
        CBEGIN = 0x53,
        CLOSURE = 0x54,
        CALLC = 0x55,
        CALL = 0x56,
        TAG = 0x57,
        FAIL = 0x59,
        LINE = 0x5a,

        PATT_STR = 0x60,
        PATT_ARR = 0x58,
        PATT_STRING = 0x61,
        PATT_ARRAY = 0x62,
        PATT_SEXP = 0x63,
        PATT_REF = 0x64,
        PATT_VAL = 0x65,
        PATT_FUN = 0x66,

        BUILTIN_READ = 0x70,
        BUILTIN_WRITE = 0x71,
        BUILTIN_LENGTH = 0x72,
        BUILTIN_STRING = 0x73,
        BUILTIN_ARRAY = 0x74,

        STOP = 0xff,
    };

    bool is_op(u8 byte) {
        switch (byte) {
        case (u8)Op::BINOP_ADD:
        case (u8)Op::BINOP_SUB:
        case (u8)Op::BINOP_MUL:
        case (u8)Op::BINOP_DIV:
        case (u8)Op::BINOP_REM:
        case (u8)Op::BINOP_LT:
        case (u8)Op::BINOP_GT:
        case (u8)Op::BINOP_LE:
        case (u8)Op::BINOP_GE:
        case (u8)Op::BINOP_EQ:
        case (u8)Op::BINOP_NE:
        case (u8)Op::BINOP_AND:
        case (u8)Op::BINOP_OR:
        case (u8)Op::CONST:
        case (u8)Op::STRING:
        case (u8)Op::SEXP:
        case (u8)Op::STI:
        case (u8)Op::STA:
        case (u8)Op::JMP:
        case (u8)Op::END:
        case (u8)Op::RET:
        case (u8)Op::DROP:
        case (u8)Op::DUP:
        case (u8)Op::SWAP:
        case (u8)Op::ELEM:
        case (u8)Op::LD_GLOBAL:
        case (u8)Op::LD_LOCAL:
        case (u8)Op::LD_ARG:
        case (u8)Op::LD_CLOSURE:
        case (u8)Op::LDA_GLOBAL:
        case (u8)Op::LDA_LOCAL:
        case (u8)Op::LDA_ARG:
        case (u8)Op::LDA_CLOSURE:
        case (u8)Op::ST_GLOBAL:
        case (u8)Op::ST_LOCAL:
        case (u8)Op::ST_ARG:
        case (u8)Op::ST_CLOSURE:
        case (u8)Op::CJMPZ:
        case (u8)Op::CJMPNZ:
        case (u8)Op::BEGIN:
        case (u8)Op::CBEGIN:
        case (u8)Op::CLOSURE:
        case (u8)Op::CALLC:
        case (u8)Op::CALL:
        case (u8)Op::TAG:
        case (u8)Op::PATT_ARR:
        case (u8)Op::FAIL:
        case (u8)Op::LINE:
        case (u8)Op::PATT_STR:
        case (u8)Op::PATT_STRING:
        case (u8)Op::PATT_ARRAY:
        case (u8)Op::PATT_SEXP:
        case (u8)Op::PATT_REF:
        case (u8)Op::PATT_VAL:
        case (u8)Op::PATT_FUN:
        case (u8)Op::BUILTIN_READ:
        case (u8)Op::BUILTIN_WRITE:
        case (u8)Op::BUILTIN_LENGTH:
        case (u8)Op::BUILTIN_STRING:
        case (u8)Op::BUILTIN_ARRAY:
        case (u8)Op::STOP:
            return true;
        default:
            return false;
        }
    }

    struct PublicEntry {
        i32 name_idx;
        i32 offset;
    };

    struct Bytecode {
        void *buffer;
        char *strings;
        usize strings_size;
        PublicEntry *public_table;
        usize public_table_size;
        void *code;
        usize code_size;
        usize globals_size;
    };

    Bytecode bytecode_from_bytes(void *buffer, usize size) {
        Bytecode bc{};
        bc.buffer = buffer;

        struct Header {
            u32 strings_size;
            u32 globals_size;
            u32 public_table_size;
        };

        if (size < sizeof(Header)) {
            throw std::runtime_error("Bytecode is too small");
        }

        Header header = *(Header *)buffer;

        bc.public_table = (PublicEntry *)((u8 *)buffer + sizeof(Header));
        bc.public_table_size = header.public_table_size;
        bc.strings = (char *)((u8 *)bc.public_table + sizeof(PublicEntry) * bc.public_table_size);
        bc.strings_size = header.strings_size;
        bc.code = (void *)((u8 *)bc.strings + bc.strings_size);

        if (size < (usize)((u8 *)bc.code - (u8 *)buffer)) {
            throw std::runtime_error("Code section does not fit in bytecode");
        }

        bc.code_size = size - (usize)((u8 *)bc.code - (u8 *)buffer);
        bc.globals_size = header.globals_size;
        return bc;
    }

    std::pair<std::vector<u8>, Bytecode> bytecode_from_file(const char *filename) {
        FILE *f;
        if (std::string(filename) == "-") {
            f = stdin;
        } else {
            f = std::fopen(filename, "rb");
            if (!f) {
                throw std::runtime_error("Failed to open file: " + std::string(filename));
            }
        }

        auto close_file = [](FILE *file) { if (file && file != stdin) std::fclose(file); };
        std::unique_ptr<FILE, decltype(close_file)> file_guard(f, close_file);

        if (std::fseek(f, 0, SEEK_END) != 0) {
            throw std::runtime_error("Failed to seek to end of file: " + std::string(filename));
        }

        long file_size = std::ftell(f);
        if (file_size < 0) {
            throw std::runtime_error("Failed to get file size: " + std::string(filename));
        }

        if (std::fseek(f, 0, SEEK_SET) != 0) {
            throw std::runtime_error("Failed to seek to start of file: " + std::string(filename));
        }

        std::vector<u8> bytecode(file_size);
        if (std::fread(bytecode.data(), file_size, 1, f) != 1) {
            throw std::runtime_error("Failed to read file: " + std::string(filename));
        }

        return {std::move(bytecode), bytecode_from_bytes(bytecode.data(), bytecode.size())};
    }

    std::vector<std::string> validate_bytecode_stage0(const Bytecode &bc) {
        std::vector<std::string> errors;

        if (auto code = (u8 *)bc.code; code[bc.code_size - 1] != 0xff) {
            errors.emplace_back("Code section must end with 0xff byte");
        }

        return errors;
    }


    struct BytecodeScanner {
        Bytecode bc;
        u32 ip;

        explicit BytecodeScanner(const Bytecode &bc) : bc(bc), ip(0) {}

        u8 byte_arg() {
            if (ip + 1 > bc.code_size) [[unlikely]] {
                throw std::runtime_error(std::format("ip 0x%08x is out of bounds", ip));
            }
            return ((u8 *)bc.code)[ip++];
        }

        Op op() {
            if (ip + 1 > bc.code_size) [[unlikely]] {
                throw std::runtime_error(std::format("ip 0x%08x is out of bounds", ip));
            }

            u8 inst = ((u8 *)bc.code)[ip];
            if (is_op(inst)) [[likely]] {
                ip++;
                return Op(inst);
            }
            throw std::runtime_error(std::format("Encountered invalid bytecode {:02x} at ip 0x{:08x}", (u32)inst, ip));
        }

        i32 arg() {
            if (ip + 4 >= bc.code_size) [[unlikely]] {
                throw std::runtime_error(std::format("ip 0x{:08x} is out of bounds", ip));
            }

            void *ptr = ((u8 *)bc.code) + ip;
            i32 result;
            std::memcpy(&result, ptr, sizeof(i32));
            ip += sizeof(i32);
            return result;
        }

        [[nodiscard]] char *get_string(i32 offset) const {
            if (offset < 0 || offset >= bc.strings_size) [[unlikely]] {
                throw std::runtime_error(std::format("String offset 0x{:08x} is out of bounds", offset));
            }
            return bc.strings + offset;
        }

        char *string_arg() {
            u32 original_ip = ip;
            i32 offset = arg();
            if (offset < 0 || offset >= bc.strings_size) [[unlikely]] {
                throw std::runtime_error(std::format("String offset 0x{:08x} required at 0x{:08x} is out of bounds", offset,
                                                     original_ip));
            }
            return bc.strings + offset;
        }
    };


    void dump_bytecode(FILE *f, const Bytecode &bc) {
        BytecodeScanner svm(bc);

        std::fprintf(f, "String table size       : %lu\n", bc.strings_size);
        std::fprintf(f, "Global area size        : %lu\n", bc.globals_size);
        std::fprintf(f, "Number of public symbols: %lu\n", bc.public_table_size);
        std::fprintf(f, "Public symbols          :\n");

        for (usize i = 0; i < bc.public_table_size; i++) {
            auto [name_offset, offset] = bc.public_table[i];
            std::fprintf(f, "   0x%.8x: %s\n", offset, svm.get_string(name_offset));
        }
        std::fprintf(f, "Code:\n");

        while (true) {
            std::fprintf(f, "0x%.8x:\t", svm.ip);
            Op op = svm.op();
            switch (op) {
            case Op::BINOP_ADD: std::fprintf(f, "BINOP\t+");
            kase Op::BINOP_SUB: std::fprintf(f, "BINOP\t-");
            kase Op::BINOP_MUL: std::fprintf(f, "BINOP\t*");
            kase Op::BINOP_DIV: std::fprintf(f, "BINOP\t/");
            kase Op::BINOP_REM: std::fprintf(f, "BINOP\t%%");
            kase Op::BINOP_LT: std::fprintf(f, "BINOP\t<");
            kase Op::BINOP_GT: std::fprintf(f, "BINOP\t>");
            kase Op::BINOP_LE: std::fprintf(f, "BINOP\t<=");
            kase Op::BINOP_GE: std::fprintf(f, "BINOP\t>=");
            kase Op::BINOP_EQ: std::fprintf(f, "BINOP\t==");
            kase Op::BINOP_NE: std::fprintf(f, "BINOP\t!=");
            kase Op::BINOP_AND: std::fprintf(f, "BINOP\t&&");
            kase Op::BINOP_OR: std::fprintf(f, "BINOP\t!!");
            kase Op::CONST: std::fprintf(f, "CONST\t%d", svm.arg());
            kase Op::STRING: std::fprintf(f, "STRING\t%s", svm.string_arg());
            kase Op::SEXP: {
                char *tag = svm.string_arg();
                i32 num_args = svm.arg();
                std::fprintf(f, "SEXP\t%s %d", tag, num_args);
            }
            kase Op::STI: std::fprintf(f, "STI");
            kase Op::STA: std::fprintf(f, "STA");
            kase Op::JMP: std::fprintf(f, "JMP\t0x%.8x", svm.arg());
            kase Op::END: std::fprintf(f, "END");
            kase Op::RET: std::fprintf(f, "RET");
            kase Op::DROP: std::fprintf(f, "DROP");
            kase Op::DUP: std::fprintf(f, "DUP");
            kase Op::SWAP: std::fprintf(f, "SWAP");
            kase Op::ELEM: std::fprintf(f, "ELEM");
            kase Op::LD_GLOBAL: std::fprintf(f, "LD\tG(%d)", svm.arg());
            kase Op::LD_LOCAL: std::fprintf(f, "LD\tL(%d)", svm.arg());
            kase Op::LD_ARG: std::fprintf(f, "LD\tA(%d)", svm.arg());
            kase Op::LD_CLOSURE: std::fprintf(f, "LD\tC(%d)", svm.arg());
            kase Op::LDA_GLOBAL: std::fprintf(f, "LDA\tG(%d)", svm.arg());
            kase Op::LDA_LOCAL: std::fprintf(f, "LDA\tL(%d)", svm.arg());
            kase Op::LDA_ARG: std::fprintf(f, "LDA\tA(%d)", svm.arg());
            kase Op::LDA_CLOSURE: std::fprintf(f, "LDA\tC(%d)", svm.arg());
            kase Op::ST_GLOBAL: std::fprintf(f, "ST\tG(%d)", svm.arg());
            kase Op::ST_LOCAL: std::fprintf(f, "ST\tL(%d)", svm.arg());
            kase Op::ST_ARG: std::fprintf(f, "ST\tA(%d)", svm.arg());
            kase Op::ST_CLOSURE: std::fprintf(f, "ST\tC(%d)", svm.arg());
            kase Op::CJMPZ: std::fprintf(f, "CJMPz\t0x%.8x", svm.arg());
            kase Op::CJMPNZ: std::fprintf(f, "CJMPnz\t0x%.8x", svm.arg());
            kase Op::BEGIN: {
                i32 args = svm.arg();
                i32 locals = svm.arg();
                std::fprintf(f, "BEGIN\t%d %d", args, locals);
            }
            kase Op::CBEGIN: {
                i32 args = svm.arg();
                i32 locals = svm.arg();
                std::fprintf(f, "CBEGIN\t%d %d", args, locals);
            }
            kase Op::CLOSURE: {
                std::fprintf(f, "CLOSURE\t0x%.8x", svm.arg());
                i32 num_captures = svm.arg();
                for (i32 i = 0; i < num_captures; i++) {
                    if (u8 designator = svm.byte_arg(); designator == 0) {
                        std::fprintf(f, "G(%d)", svm.arg());
                    } else if (designator == 1) {
                        std::fprintf(f, "L(%d)", svm.arg());
                    } else if (designator == 2) {
                        std::fprintf(f, "A(%d)", svm.arg());
                    } else if (designator == 3) {
                        std::fprintf(f, "C(%d)", svm.arg());
                    } else {
                        throw std::runtime_error(std::format("Invalid capture designator %d", num_captures));
                    }
                }
            }
            kase Op::CALLC: std::fprintf(f, "CALLC\t%d", svm.arg());
            kase Op::CALL: {
                i32 offset = svm.arg();
                i32 num_args = svm.arg();
                std::fprintf(f, "CALL\t0x%.8x %d", offset, num_args);
            }
            kase Op::TAG: {
                char *s = svm.string_arg();
                i32 num = svm.arg();
                std::fprintf(f, "TAG\t%s %d", s, num);
            }
            kase Op::PATT_ARR: std::fprintf(f, "ARRAY\t%d", svm.arg());
            kase Op::FAIL: {
                i32 line = svm.arg();
                i32 column = svm.arg();
                std::fprintf(f, "FAIL\t%d %d", line, column);
            }
            kase Op::LINE: std::fprintf(f, "LINE\t%d", svm.arg());
            kase Op::PATT_STR: std::fprintf(f, "PATT\t=str");
            kase Op::PATT_STRING: std::fprintf(f, "PATT\t#string");
            kase Op::PATT_ARRAY: std::fprintf(f, "PATT\t#array");
            kase Op::PATT_SEXP: std::fprintf(f, "PATT\t#sexp");
            kase Op::PATT_REF: std::fprintf(f, "PATT\t#ref");
            kase Op::PATT_VAL: std::fprintf(f, "PATT\t#val");
            kase Op::PATT_FUN: std::fprintf(f, "PATT\t#fun");
            kase Op::BUILTIN_READ: std::fprintf(f, "CALL\tLread");
            kase Op::BUILTIN_WRITE: std::fprintf(f, "CALL\tLwrite");
            kase Op::BUILTIN_LENGTH: std::fprintf(f, "CALL\tLlength");
            kase Op::BUILTIN_STRING: std::fprintf(f, "CALL\tLstring");
            kase Op::BUILTIN_ARRAY: std::fprintf(f, "CALL\tBarray\t%d", svm.arg());
            kase Op::STOP: std::fprintf(f, "<end>");
            }
            std::fprintf(f, "\n");
            if (op == Op::STOP) break;
        }
    }
}

namespace il {
    enum class Op : u8 {
        BINOP_ADD = 1,
        BINOP_SUB,
        BINOP_MUL,
        BINOP_DIV,
        BINOP_REM,
        BINOP_LT,
        BINOP_LE,
        BINOP_GT,
        BINOP_GE,
        BINOP_EQ,
        BINOP_NE,
        BINOP_AND,
        BINOP_OR,

        CONST, // aint
        STRING, // char *
        SEXP, // char *, u32
        STI,
        STA,
        JMP, // u32
        END,
        RET,
        DROP,
        DUP,
        SWAP,
        ELEM,

        // all have u32 arg
        LD_GLOBAL,
        LD_LOCAL,
        LD_ARG,
        LD_CLOSURE,
        LDA_GLOBAL,
        LDA_LOCAL,
        LDA_ARG,
        LDA_CLOSURE,
        ST_GLOBAL,
        ST_LOCAL,
        ST_ARG,
        ST_CLOSURE,

        CJMPZ,
        CJMPNZ,
        BEGIN, // u32 u32
        CBEGIN, // u32 u32
        CLOSURE, // u32
        CALLC, // u32
        CALL, // u32 u32
        TAG, // char *, u32
        PATT_ARR, // u32
        FAIL, // u32 u32
        LINE, // u32

        PATT_STR,
        PATT_STRING,
        PATT_ARRAY,
        PATT_SEXP,
        PATT_REF,
        PATT_VAL,
        PATT_FUN,

        BUILTIN_READ,
        BUILTIN_WRITE,
        BUILTIN_LENGTH,
        BUILTIN_STRING,
        BUILTIN_ARRAY,

        NOP,
        POP_CC,
    };

    u32 dump_instruction(u8 *code, u32 ip) {
        std::printf("%08x: ", ip);

        auto read_u32 = [&code, &ip]() -> u32 {
            u32 result;
            std::memcpy(&result, code + ip, sizeof(u32));
            ip += sizeof(u32);
            return result;
        };

        auto read_ptr = [&code, &ip]() -> void * {
            void *result;
            std::memcpy(&result, code + ip, sizeof(void *));
            ip += sizeof(void *);
            return result;
        };

        switch (auto op = (Op)code[ip++]) {
            case Op::BINOP_ADD: std::printf("BINOP_ADD");
            kase Op::BINOP_SUB: std::printf("BINOP_SUB");
            kase Op::BINOP_MUL: std::printf("BINOP_MUL");
            kase Op::BINOP_DIV: std::printf("BINOP_DIV");
            kase Op::BINOP_REM: std::printf("BINOP_REM");
            kase Op::BINOP_LT: std::printf("BINOP_LT");
            kase Op::BINOP_LE: std::printf("BINOP_LE");
            kase Op::BINOP_GT: std::printf("BINOP_GT");
            kase Op::BINOP_GE: std::printf("BINOP_GE");
            kase Op::BINOP_EQ: std::printf("BINOP_EQ");
            kase Op::BINOP_NE: std::printf("BINOP_NE");
            kase Op::BINOP_AND: std::printf("BINOP_AND");
            kase Op::BINOP_OR: std::printf("BINOP_OR");

            kase Op::STI: std::printf("STI");
            kase Op::STA: std::printf("STA");
            kase Op::END: std::printf("END");
            kase Op::RET: std::printf("RET");
            kase Op::DROP: std::printf("DROP");
            kase Op::DUP: std::printf("DUP");
            kase Op::SWAP: std::printf("SWAP");
            kase Op::ELEM: std::printf("ELEM");

            kase Op::JMP: std::printf("JMP 0x%08x", read_u32());
            kase Op::CJMPZ: std::printf("CJMPZ 0x%08x", read_u32());
            kase Op::CJMPNZ: std::printf("CJMPNZ 0x%08x", read_u32());

            kase Op::LD_GLOBAL: std::printf("LD_GLOBAL %u", read_u32());
            kase Op::LD_LOCAL: std::printf("LD_LOCAL %u", read_u32());
            kase Op::LD_ARG: std::printf("LD_ARG %u", read_u32());
            kase Op::LD_CLOSURE: std::printf("LD_CLOSURE %u", read_u32());
            kase Op::LDA_GLOBAL: std::printf("LDA_GLOBAL %u", read_u32());
            kase Op::LDA_LOCAL: std::printf("LDA_LOCAL %u", read_u32());
            kase Op::LDA_ARG: std::printf("LDA_ARG %u", read_u32());
            kase Op::LDA_CLOSURE: std::printf("LDA_CLOSURE %u", read_u32());
            kase Op::ST_GLOBAL: std::printf("ST_GLOBAL %u", read_u32());
            kase Op::ST_LOCAL: std::printf("ST_LOCAL %u", read_u32());
            kase Op::ST_ARG: std::printf("ST_ARG %u", read_u32());
            kase Op::ST_CLOSURE: std::printf("ST_CLOSURE %u", read_u32());

            kase Op::CONST: std::printf("CONST %ld", UNBOX(read_u32()));
            kase Op::STRING: {
                auto str = (const char *)read_ptr();
                std::printf("STRING \"%s\"", str);
            }
            kase Op::SEXP: {
                auto tag = (const char *)read_ptr();
                u32 num_args = read_u32();
                std::printf("SEXP \"%s\" %u", tag, num_args);
            }

            kase Op::BEGIN: {
                u32 locals = read_u32();
                u32 args = read_u32();
                std::printf("BEGIN locals=%u, args=%u", locals, args);
            }
            kase Op::CBEGIN: {
                u32 locals = read_u32();
                u32 args = read_u32();
                std::printf("CBEGIN locals=%u, args=%u", locals, args);
            }
            kase Op::CLOSURE: {
                u32 num_args = read_u32();
                std::printf("CLOSURE args=%u", num_args);
            }
            kase Op::CALL: {
                u32 offset = read_u32();
                u32 num_args = read_u32();
                std::printf("CALL 0x%08x args=%u", offset, num_args);
            }
            kase Op::CALLC: {
                u32 num_args = read_u32();
                std::printf("CALLC args=%u", num_args);
            }

            kase Op::PATT_STR:    std::printf("PATT_STR");
            kase Op::PATT_STRING: std::printf("PATT_STRING");
            kase Op::PATT_ARRAY:  std::printf("PATT_ARRAY");
            kase Op::PATT_SEXP:   std::printf("PATT_SEXP");
            kase Op::PATT_REF:    std::printf("PATT_REF");
            kase Op::PATT_VAL:    std::printf("PATT_VAL");
            kase Op::PATT_FUN:    std::printf("PATT_FUN");

            kase Op::BUILTIN_READ:   std::printf("BUILTIN_READ");
            kase Op::BUILTIN_WRITE:  std::printf("BUILTIN_WRITE");
            kase Op::BUILTIN_LENGTH: std::printf("BUILTIN_LENGTH");
            kase Op::BUILTIN_STRING: std::printf("BUILTIN_STRING");
            kase Op::BUILTIN_ARRAY:  std::printf("BUILTIN_ARRAY %d", read_u32());

            kase Op::TAG: {
                auto tag = (char *)read_ptr();
                std::printf("TAG \"%s\" %u", tag, read_u32());
            }
            kase Op::PATT_ARR: std::printf("ARRAY %u", read_u32());
            kase Op::FAIL: std::printf("FAIL %u", read_u32());
            kase Op::LINE: std::printf("LINE %u", read_u32());
            kase Op::NOP: std::printf("NOP");
            kase Op::POP_CC: std::printf("POP_CC");
            otherwise: std::printf("UNKNOWN_OP(%u)", static_cast<u8>(op));
        }
        
        std::printf("\n");
        return ip;
    }

    union Value {
        aint number;
        void *ptr;
    };

    struct ReturnStackEntry {
        u32 ip;
        u32 fp;
        u32 lp;
        u32 bp;
    };

    struct VmConfig {
        std::string filename;
        usize stack_size;
        usize rstack_size;
    };

    enum class ExecutionError {
        END,
        STACK_OVERFLOW,
        STACK_UNDERFLOW,
        RETURN_STACK_OVERFLOW,
        INTEGER_EXPECTED,
        NAME_NOT_FOUND,
        LOCAL_SLOT_OUT_OF_BOUNDS,
        ARITHMETIC_ERROR,
        ARG_SLOT_OUT_OF_BOUNDS,
        POINTER_EXPECTED,
        TOO_MANY_ARGUMENTS,
        STACK_INCONSISTENT,
        NOT_IN_CLOSURE,
    };

    struct Vm {
        std::unique_ptr<u8 []> code;
        std::unique_ptr<Value []> stack;
        std::unique_ptr<ReturnStackEntry []> rstack;
        std::unique_ptr<u8 []> consts;
        std::unordered_map<std::string, u32> global_functions;
        std::vector<std::pair<u32, u32>> line_mapping;
        std::string filename;
        u32 globals_size;
        u32 ip; // instruction pointer
        u32 sp; // stack pointer
        u32 rsp; // return stack pointer
        u32 fp; // frame pointer (arguments)
        u32 lp; // local variables pointer (locals)
        u32 bp; // base pointer (temporaries)
        u32 stack_top;
        u32 rstack_top;
        void *cc; // current closure register
    };

    std::variant<Vm, std::vector<std::string>> build_vm(VmConfig cfg, el::Bytecode bc) {
        std::vector<std::string> errors;

        std::vector<u8> code;
        code.reserve(bc.code_size * 3 / 2);

        std::unordered_map<std::string, usize> interned_strings;
        std::vector<u8> consts;

        std::vector<std::pair<u32, u32>> offset_remapping;
        std::vector<u32> offsets_to_fix;
        std::vector<u32> consts_to_fix;
        std::vector<std::pair<u32, u32>> line_mapping;

        el::BytecodeScanner scanner(bc);

        auto intern_string = [&interned_strings, &consts](const char *str) {
            if (auto it = interned_strings.find(str); it != interned_strings.end()) {
                return it->second;
            }
            if (auto size = consts.size(); size % alignof(aint) != 0) {
                consts.insert(consts.end(), alignof(aint) - size % alignof(aint), 0);
            }
            auto idx = consts.size();
            consts.insert(consts.end(), str, str + std::strlen(str) + 1);
            interned_strings[str] = idx;
            return idx;
        };

        auto empty_string = intern_string("");

        while (true) {
            auto write_op = [&code](Op op) {
                code.push_back((u8)op);
            };

#define WRITE_VALUE(val) { \
    auto __x = (val); \
    u8 __buf[sizeof(__x)]; \
    std::memcpy(__buf, &__x, sizeof(__x)); \
    code.insert(code.end(), __buf, __buf + sizeof(__x)); \
}

            offset_remapping.emplace_back(scanner.ip, code.size());
            auto op = scanner.op();
            switch (op) {
            case el::Op::BINOP_ADD: write_op(Op::BINOP_ADD);
            kase el::Op::BINOP_SUB: write_op(Op::BINOP_SUB);
            kase el::Op::BINOP_MUL: write_op(Op::BINOP_MUL);
            kase el::Op::BINOP_DIV: write_op(Op::BINOP_DIV);
            kase el::Op::BINOP_REM: write_op(Op::BINOP_REM);
            kase el::Op::BINOP_LT: write_op(Op::BINOP_LT);
            kase el::Op::BINOP_LE: write_op(Op::BINOP_LE);
            kase el::Op::BINOP_GT: write_op(Op::BINOP_GT);
            kase el::Op::BINOP_GE: write_op(Op::BINOP_GE);
            kase el::Op::BINOP_EQ: write_op(Op::BINOP_EQ);
            kase el::Op::BINOP_NE: write_op(Op::BINOP_NE);
            kase el::Op::BINOP_AND: write_op(Op::BINOP_AND);
            kase el::Op::BINOP_OR: write_op(Op::BINOP_OR);
            kase el::Op::CONST: {
                write_op(Op::CONST);
                auto val = (aint)scanner.arg();
                WRITE_VALUE(BOX(val));
            }
            kase el::Op::STRING: {
                write_op(Op::STRING);
                auto offset = (u32)scanner.arg();
                consts_to_fix.push_back(code.size());
                if (offset >= bc.strings_size) {
                    errors.emplace_back(std::format("String offset {} is out of bounds", offset));
                    WRITE_VALUE(empty_string);
                } else {
                    WRITE_VALUE(intern_string(bc.strings + offset));
                }
            }
            kase el::Op::JMP: {
                write_op(Op::JMP);
                auto offset = (u32)scanner.arg();
                offsets_to_fix.push_back(code.size());
                WRITE_VALUE(offset);
            }
            kase el::Op::CJMPZ: {
                write_op(Op::CJMPZ);
                auto offset = (u32)scanner.arg();
                offsets_to_fix.push_back(code.size());
                WRITE_VALUE(offset);
            }
            kase el::Op::CJMPNZ: {
                write_op(Op::CJMPNZ);
                auto offset = (u32)scanner.arg();
                offsets_to_fix.push_back(code.size());
                WRITE_VALUE(offset);
            }
            kase el::Op::BEGIN: {
                write_op(Op::BEGIN);
                auto args = (u32)scanner.arg();
                auto locals = (u32)scanner.arg();
                WRITE_VALUE(args);
                WRITE_VALUE(locals);
            }
            kase el::Op::END: {
                write_op(Op::END);
            }
            kase el::Op::LINE: {
                auto line = (u32)scanner.arg();
                line_mapping.emplace_back(scanner.ip, line);
            }
            kase el::Op::STA: {
                write_op(Op::STA);
            }
            kase el::Op::ELEM: {
                write_op(Op::ELEM);
            }
            kase el::Op::ST_GLOBAL: {
                write_op(Op::ST_GLOBAL);
                auto offset = (u32)scanner.arg();
                WRITE_VALUE(offset);
            }
            kase el::Op::ST_LOCAL: {
                write_op(Op::ST_LOCAL);
                auto offset = (u32)scanner.arg();
                WRITE_VALUE(offset);
            }
            kase el::Op::ST_ARG: {
                write_op(Op::ST_ARG);
                auto offset = (u32)scanner.arg();
                WRITE_VALUE(offset);
            }
            kase el::Op::ST_CLOSURE: {
                write_op(Op::ST_CLOSURE);
                auto offset = (u32)scanner.arg();
                WRITE_VALUE(offset);
            }
            kase el::Op::LD_GLOBAL: {
                write_op(Op::LD_GLOBAL);
                auto offset = (u32)scanner.arg();
                if (offset >= bc.globals_size) {
                    errors.emplace_back(std::format("Global offset {} is out of bounds", offset));
                }
                WRITE_VALUE(offset);
            }
            kase el::Op::LD_LOCAL: {
                write_op(Op::LD_LOCAL);
                auto offset = (u32)scanner.arg();
                WRITE_VALUE(offset);
            }
            kase el::Op::LD_ARG: {
                write_op(Op::LD_ARG);
                auto offset = (u32)scanner.arg();
                WRITE_VALUE(offset);
            }
            kase el::Op::LD_CLOSURE: {
                write_op(Op::LD_CLOSURE);
                auto offset = (u32)scanner.arg();
                WRITE_VALUE(offset);
            }
            kase el::Op::DROP: {
                write_op(Op::DROP);
            }
            kase el::Op::DUP: {
                write_op(Op::DUP);
            }
            kase el::Op::CALL: {
                write_op(Op::CALL);
                auto offset = (u32)scanner.arg();
                offsets_to_fix.push_back(code.size());
                auto num_args = (u32)scanner.arg();
                WRITE_VALUE(offset);
                WRITE_VALUE(num_args);
            }
            kase el::Op::BUILTIN_READ: {
                write_op(Op::BUILTIN_READ);
            }
            kase el::Op::BUILTIN_WRITE: {
                write_op(Op::BUILTIN_WRITE);
            }
            kase el::Op::BUILTIN_STRING: {
                write_op(Op::BUILTIN_STRING);
            }
            kase el::Op::BUILTIN_LENGTH: {
                write_op(Op::BUILTIN_LENGTH);
            }
            kase el::Op::BUILTIN_ARRAY: {
                write_op(Op::BUILTIN_ARRAY);
                auto num_args = (u32)scanner.arg();
                WRITE_VALUE(num_args);
            }
            kase el::Op::TAG: {
                write_op(Op::TAG);
                auto offset = (u32)scanner.arg();
                consts_to_fix.push_back(code.size());
                if (offset >= bc.strings_size) {
                    errors.emplace_back(std::format("String offset {} is out of bounds", offset));
                    WRITE_VALUE(empty_string);
                } else {
                    WRITE_VALUE(intern_string(bc.strings + offset));
                }
                auto num_args = (u32)scanner.arg();
                WRITE_VALUE(num_args);
            }
            kase el::Op::SEXP: {
                write_op(Op::SEXP);
                auto offset = (u32)scanner.arg();
                consts_to_fix.push_back(code.size());
                if (offset >= bc.strings_size) {
                    errors.emplace_back(std::format("String offset {} is out of bounds", offset));
                    WRITE_VALUE(empty_string);
                } else {
                    WRITE_VALUE(intern_string(bc.strings + offset));
                }
                auto num_args = (u32)scanner.arg();
                WRITE_VALUE(num_args);
            }
            kase el::Op::FAIL: {
                auto line = scanner.arg();
                auto column = scanner.arg();
                write_op(Op::FAIL);
                WRITE_VALUE(line);
                WRITE_VALUE(column);
            }
            kase el::Op::CLOSURE: {
                auto fn_offset = (u32)scanner.arg();
                auto num_args = (u32)scanner.arg();
                write_op(Op::CONST);
                // instead of storing function pointer we store offset in bytecode
#if __BYTE_ORDER == __LITTLE_ENDIAN
                offsets_to_fix.push_back(code.size());
#else
                offsets_to_fix.push_back(code.size() + (sizeof(aint) - sizeof(u32)));
#endif
                WRITE_VALUE((aint)fn_offset);
                for (u32 i = 0; i < num_args; ++i) {
                    auto designator = scanner.byte_arg();
                    auto offset = (u32)scanner.arg();
                    switch (designator) {
                    case 0:
                        write_op(Op::LD_GLOBAL);
                        WRITE_VALUE(offset);
                    kase 1:
                        write_op(Op::LD_LOCAL);
                        WRITE_VALUE(offset);
                    kase 2:
                        write_op(Op::LD_ARG);
                        WRITE_VALUE(offset);
                    kase 3:
                        write_op(Op::LD_CLOSURE);
                        WRITE_VALUE(offset);
                    otherwise:
                        errors.emplace_back(std::format("Unsupported designator {}", designator));
                        for (int j = 0; j < sizeof(offset) + 1; ++j) {
                            write_op(Op::NOP);
                        }
                    }
                }

                write_op(Op::CLOSURE);
                WRITE_VALUE(num_args);
            }
            kase el::Op::CALLC: {
                auto num_args = (u32)scanner.arg();
                write_op(Op::CALLC);
                WRITE_VALUE(num_args);
                write_op(Op::POP_CC);
            }
            kase el::Op::CBEGIN: {
                write_op(Op::BEGIN);
                auto args = (u32)scanner.arg();
                auto locals = (u32)scanner.arg();
                WRITE_VALUE(args);
                WRITE_VALUE(locals);
            }
            kase el::Op::RET:
                errors.emplace_back("RET is not supported because it is not generated");
            kase el::Op::PATT_STR: write_op(Op::PATT_STR);
            kase el::Op::PATT_ARR: {
                write_op(Op::PATT_ARR);
                WRITE_VALUE(scanner.arg());
            }
            kase el::Op::PATT_STRING: write_op(Op::PATT_STRING);
            kase el::Op::PATT_ARRAY: write_op(Op::PATT_ARRAY);
            kase el::Op::PATT_SEXP: write_op(Op::PATT_SEXP);
            kase el::Op::PATT_REF: write_op(Op::PATT_REF);
            kase el::Op::PATT_VAL: write_op(Op::PATT_VAL);
            kase el::Op::PATT_FUN: write_op(Op::PATT_FUN);
            kase el::Op::STOP:
                break;
            otherwise:
                errors.emplace_back(std::format("Unsupported operation {:02x} at {:08x}", (u32)op, scanner.ip));
                return std::move(errors);
            }
            if (op == el::Op::STOP) {
                for (int i = 0; i < 32; ++i) {
                    write_op(Op::NOP);
                }
                write_op(Op::FAIL);
                WRITE_VALUE((u32)0);
                WRITE_VALUE((u32)0);
                break;
            }
        }

#undef WRITE_VALUE

        auto find_code_offset = [&offset_remapping](u32 offset) -> std::optional<u32> {
            auto it = std::lower_bound(
                offset_remapping.begin(),
                offset_remapping.end(),
                offset,
                [](auto ei, auto x) { return ei.first < x; }
            );
            if (it == offset_remapping.end() || it->first != offset) {
                return std::nullopt;
            }
            return it->second;
        };

        for (u32 fixing_offset : offsets_to_fix) {
            u32 offset;
            std::memcpy(&offset, code.data() + fixing_offset, sizeof(u32));
            auto it = find_code_offset(offset);
            if (!it) {
                errors.emplace_back(std::format("Invalid code offset: {}", offset));
                return std::move(errors);
            }
            u32 value = *it;
            std::memcpy(code.data() + fixing_offset, &value, sizeof(u32));
        }

        auto pinned_consts = pin_array(std::move(consts));

        for (u32 fixing_offset : consts_to_fix) {
            auint offset;
            std::memcpy(&offset, code.data() + fixing_offset, sizeof(aint));
            void *ptr = pinned_consts.get() + offset;
            std::memcpy(code.data() + fixing_offset, &ptr, sizeof(void *));
        }

        std::unordered_map<std::string, u32> global_functions;

        for (usize i = 0; i < bc.public_table_size; ++i) {
            auto &entry = bc.public_table[i];
            std::string name(scanner.get_string(entry.name_idx));
            auto it = find_code_offset(entry.offset);
            if (!it) {
                errors.emplace_back(std::format("Public function {} at illegal offset {}", name, entry.offset));
                return std::move(errors);
            }
            global_functions[name] = *it;
        }

        auto pinned_code = pin_array(std::move(code));

        auto full_stack_size = bc.globals_size + cfg.stack_size;
        auto pinned_stack = std::unique_ptr<Value []>(new Value[full_stack_size]);
        auto pinned_rstack = std::unique_ptr<ReturnStackEntry []>(new ReturnStackEntry[cfg.rstack_size]);

        std::fill_n(pinned_stack.get(), bc.globals_size, Value{.number = BOX(0)});

        return Vm{
            .code = std::move(pinned_code),
            .stack = std::move(pinned_stack),
            .rstack = std::move(pinned_rstack),
            .consts = std::move(pinned_consts),
            .global_functions = std::move(global_functions),
            .line_mapping = std::move(line_mapping),
            .filename = std::move(cfg.filename),
            .globals_size = (u32)bc.globals_size,
            .ip = 0,
            .sp = (u32)bc.globals_size,
            .rsp = 0,
            .fp = (u32)bc.globals_size,
            .lp = (u32)bc.globals_size,
            .bp = (u32)bc.globals_size,
            .stack_top = (u32)full_stack_size,
            .rstack_top = (u32)cfg.rstack_size,
            .cc = nullptr,
        };
    }

    void dump_stacks(const Vm &vm) {
        std::printf("====================\n");
        for (int i = 0; i < vm.rsp; i++) {
            std::printf("%3d rp=%08x fp=%08x lp=%08x\n", i, vm.rstack[i].ip, vm.rstack[i].fp, vm.rstack[i].lp);
        }
        std::printf("====================\n");
        for (int i = 0; i < vm.sp; i++) {
            if (i == vm.globals_size && i > 0) {
                std::printf("^^^ GLOBALS ^^^\n");
            }
            if (UNBOXED(vm.stack[i].number)) {
                std::printf("%3d %016lx %ld", i, vm.stack[i].number, UNBOX(vm.stack[i].number));
            } else {
                std::printf("%3d %016lx %p", i, vm.stack[i].number, vm.stack[i].ptr);
            }
            if (i == vm.fp) std::printf(" <fp");
            if (i == vm.lp) std::printf(" <lp");
            if (i == vm.bp) std::printf(" <bp");
            std::printf("\n");
        }
    }

    void gc_update(const Vm &vm) {
        __gc_stack_top = (usize)vm.stack.get() - sizeof(void *);
        __gc_stack_bottom = (usize)(vm.stack.get() + vm.sp);
    }

    ExecutionError vm_continue(Vm &vm, bool trace = false) {
#define ESCAPE(varname) CONCAT(varname, _VAL)

#define POP(varname) \
if (vm.sp <= vm.bp) return ExecutionError::STACK_UNDERFLOW; \
auto varname = vm.stack[--vm.sp];

#define PEEK(varname) \
if (vm.sp <= vm.bp) return ExecutionError::STACK_UNDERFLOW; \
auto varname = vm.stack[vm.sp - 1];

#define POP2(varname, varname2) \
if (--vm.sp <= vm.bp) return ExecutionError::STACK_UNDERFLOW; \
auto varname2 = vm.stack[vm.sp]; \
auto varname = vm.stack[--vm.sp]

#define POP_NUM(varname) \
POP(ESCAPE(varname)); \
if (!UNBOXED(ESCAPE(varname).number)) return ExecutionError::INTEGER_EXPECTED; \
aint varname = UNBOX(ESCAPE(varname).number)

#define POP2_NUM(varname, varname2) \
POP2(ESCAPE(varname), ESCAPE(varname2)); \
if (!UNBOXED(ESCAPE(varname2).number)) return ExecutionError::INTEGER_EXPECTED; \
if (!UNBOXED(ESCAPE(varname).number)) return ExecutionError::INTEGER_EXPECTED; \
aint varname = UNBOX(ESCAPE(varname).number); \
aint varname2 = UNBOX(ESCAPE(varname2).number)

#define POP_PTR(varname) \
POP(ESCAPE(varname)); \
if (UNBOXED(ESCAPE(varname).number)) return ExecutionError::POINTER_EXPECTED; \
void *varname = ESCAPE(varname).ptr

#define PUSH(expr) { \
if (vm.sp >= vm.stack_top) return ExecutionError::STACK_OVERFLOW; \
auto __res = (expr); \
vm.stack[vm.sp++] = __res; \
}

#define PUSH_PTR(expr) PUSH(Value { .ptr = (expr) })
#define PUSH_NUM_ASSUME_BOXED(expr) PUSH(Value { .number = expr })
#define PUSH_NUM(expr) PUSH_NUM_ASSUME_BOXED(BOX(expr))

#define FETCH_OP() (Op)vm.code[vm.ip++]
#define FETCH_VALUE(ty, varname) \
ty varname; \
std::memcpy(&varname, vm.code.get() + vm.ip, sizeof(varname)); \
vm.ip += sizeof(varname)

        while (true) {
            if (trace) {
                dump_stacks(vm);
                dump_instruction(vm.code.get(), vm.ip);
            }
            switch (FETCH_OP()) {
            case Op::NOP:
                break;
            kase Op::BINOP_ADD: {
                POP2_NUM(a, b);
                // technically UB because signed overflow,
                // but it's not like compiler is going to generate
                // something creative
                PUSH_NUM(a + b);
            }
            kase Op::BINOP_SUB: {
                POP2_NUM(a, b);
                PUSH_NUM(a - b);
            }
            kase Op::BINOP_MUL: {
                POP2_NUM(a, b);
                PUSH_NUM(a * b);
            }
            kase Op::BINOP_DIV: {
                POP2_NUM(a, b);
                if (b == 0) return ExecutionError::ARITHMETIC_ERROR;
                PUSH_NUM(a / b);
            }
            kase Op::BINOP_REM: {
                POP2_NUM(a, b);
                if (b == 0) return ExecutionError::ARITHMETIC_ERROR;
                PUSH_NUM(a % b);
            }
            kase Op::BINOP_LT: {
                POP2_NUM(a, b);
                PUSH_NUM((aint)(a < b));
            }
            kase Op::BINOP_GT: {
                POP2_NUM(a, b);
                PUSH_NUM((aint)(a > b));
            }
            kase Op::BINOP_LE: {
                POP2_NUM(a, b);
                PUSH_NUM((aint)(a <= b));
            }
            kase Op::BINOP_GE: {
                POP2_NUM(a, b);
                PUSH_NUM((aint)(a >= b));
            }
            kase Op::BINOP_EQ: {
                POP2(a, b);
                PUSH_NUM((aint)(a.number == b.number));
            }
            kase Op::BINOP_NE: {
                POP2(a, b);
                PUSH_NUM((aint)(a.number != b.number));
            }
            kase Op::BINOP_AND: {
                POP2_NUM(a, b);
                PUSH_NUM((aint)(a && b));
            }
            kase Op::BINOP_OR: {
                POP2_NUM(a, b);
                PUSH_NUM((aint)(a || b));
            }
            kase Op::CONST: {
                FETCH_VALUE(aint, x);
                PUSH_NUM_ASSUME_BOXED(x);
            }
            kase Op::STRING: {
                FETCH_VALUE(aint, s);
                gc_update(vm);
                auto x = Bstring(&s);
                PUSH_PTR(x);
            }
            kase Op::JMP: {
                FETCH_VALUE(u32, offset);
                vm.ip = offset;
            }
            kase Op::CJMPZ: {
                POP(cond);
                FETCH_VALUE(u32, offset);
                if (cond.number == BOX(0)) {
                    vm.ip = offset;
                }
            }
            kase Op::CJMPNZ: {
                POP(cond);
                FETCH_VALUE(u32, offset);
                if (cond.number != BOX(0)) {
                    vm.ip = offset;
                }
            }
            kase Op::BEGIN: {
                FETCH_VALUE(u32, args);
                FETCH_VALUE(u32, locals);
                if (vm.sp - vm.lp < args) {
                    return ExecutionError::TOO_MANY_ARGUMENTS;
                }
                vm.fp = vm.sp - args;
                vm.lp = vm.sp;
                for (u32 i = 0; i < locals; ++i) {
                    vm.stack[vm.sp++].number = BOX(0);
                }
                vm.bp = vm.sp;
            }
            kase Op::END: {
                POP(ret);
                if (vm.sp != vm.bp) {
                    return ExecutionError::STACK_INCONSISTENT;
                }
                auto &entry = vm.rstack[--vm.rsp];
                vm.sp = vm.fp;
                vm.ip = entry.ip;
                vm.fp = entry.fp;
                vm.lp = entry.lp;
                vm.bp = entry.bp;
                if (vm.rsp == 0) [[unlikely]] {
                    return ExecutionError::END;
                }
                PUSH(ret);
            }
            kase Op::DROP: {
                POP(_);
            }
            kase Op::DUP: {
                PEEK(x);
                PUSH(x);
            }
            kase Op::ELEM: {
                POP(i);
                POP_PTR(x);
                PUSH_PTR(Belem(x, i.number));
            }
            kase Op::STA: {
                POP(v);
                POP(i);
                POP_PTR(x);
                PUSH_PTR(Bsta(x, i.number, v.ptr));
            }
            kase Op::LD_GLOBAL: {
                FETCH_VALUE(u32, offset);
                // global offsets are checked for out of bounds already
                PUSH(vm.stack[offset]);
            }
            kase Op::LD_LOCAL: {
                FETCH_VALUE(u32, offset);
                if (vm.lp + offset >= vm.bp) return ExecutionError::LOCAL_SLOT_OUT_OF_BOUNDS;
                PUSH(vm.stack[vm.lp + offset]);
            }
            kase Op::LD_ARG: {
                FETCH_VALUE(u32, offset);
                if (vm.fp + offset >= vm.lp) return ExecutionError::ARG_SLOT_OUT_OF_BOUNDS;
                PUSH(vm.stack[vm.fp + offset]);
            }
            kase Op::LD_CLOSURE: {
                if (vm.cc == nullptr) return ExecutionError::NOT_IN_CLOSURE;
                FETCH_VALUE(u32, offset);
                PUSH_PTR(Belem(vm.cc, BOX((aint)offset + 1)));
            }
            kase Op::ST_GLOBAL: {
                PEEK(x);
                FETCH_VALUE(u32, offset);
                vm.stack[offset] = x;
            }
            kase Op::ST_LOCAL: {
                PEEK(x);
                FETCH_VALUE(u32, offset);
                if (vm.lp + offset >= vm.bp) return ExecutionError::LOCAL_SLOT_OUT_OF_BOUNDS;
                vm.stack[vm.lp + offset] = x;
            }
            kase Op::ST_ARG: {
                PEEK(x);
                FETCH_VALUE(u32, offset);
                if (vm.fp + offset >= vm.lp) return ExecutionError::ARG_SLOT_OUT_OF_BOUNDS;
                vm.stack[vm.fp + offset] = x;
            }
            kase Op::ST_CLOSURE: {
                if (vm.cc == nullptr) return ExecutionError::NOT_IN_CLOSURE;
                POP(x);
                FETCH_VALUE(u32, offset);
                PUSH_PTR(Bsta(vm.cc, BOX((aint)offset + 1), x.ptr));
            }
            kase Op::CALL: {
                FETCH_VALUE(u32, offset);
                FETCH_VALUE(u32, num_args);
                if (vm.rsp >= vm.rstack_top) return ExecutionError::STACK_OVERFLOW;
                auto &entry = vm.rstack[vm.rsp++];
                entry.ip = vm.ip;
                entry.fp = vm.fp;
                entry.lp = vm.lp;
                entry.bp = vm.bp;
                vm.ip = offset;
            }
            kase Op::BUILTIN_READ: {
                PUSH_NUM_ASSUME_BOXED(Lread());
            }
            kase Op::BUILTIN_WRITE: {
                POP(x);
                Lwrite(x.number);
                PUSH_NUM(0);
            }
            kase Op::BUILTIN_LENGTH: {
                POP_PTR(x);
                PUSH_NUM_ASSUME_BOXED(Llength(x));
            }
            kase Op::BUILTIN_ARRAY: {
                FETCH_VALUE(u32, num_args);
                if (vm.sp - vm.bp < num_args) {
                    return ExecutionError::TOO_MANY_ARGUMENTS;
                }

                gc_update(vm);
                vm.sp -= num_args;
                PUSH_PTR(Barray((aint *)vm.stack.get() + vm.sp, BOX(num_args)));
            }
            kase Op::BUILTIN_STRING: {
                gc_update(vm);
                POP(x);
                PUSH_PTR(Lstring(&x.number));
            }
            kase Op::SEXP: {
                FETCH_VALUE(char *, tag);
                FETCH_VALUE(u32, num_args);
                if (vm.sp - vm.bp < num_args) {
                    return ExecutionError::TOO_MANY_ARGUMENTS;
                }
                aint tag_hash = LtagHash(tag);
                vm.stack[vm.sp].number = tag_hash;

                gc_update(vm);
                vm.sp -= num_args;
                PUSH_PTR(Bsexp((aint *)vm.stack.get() + vm.sp, BOX(num_args + 1)));
            }
            kase Op::TAG: {
                FETCH_VALUE(char *, tag);
                FETCH_VALUE(u32, num_args);
                aint tag_hash = LtagHash(tag);
                POP(x);
                PUSH_NUM_ASSUME_BOXED(Btag(x.ptr, tag_hash, BOX(num_args)));
            }
            kase Op::FAIL: {
                FETCH_VALUE(u32, line);
                FETCH_VALUE(u32, column);
                Bmatch_failure(vm.stack.get(), vm.filename.c_str(), line, column);
            }
            kase Op::CLOSURE: {
                FETCH_VALUE(u32, num_args);
                if (vm.sp - vm.bp < num_args) {
                    return ExecutionError::TOO_MANY_ARGUMENTS;
                }

                gc_update(vm);
                vm.sp -= num_args + 1;
                PUSH_PTR(Bclosure((aint *)vm.stack.get() + vm.sp, BOX(num_args)));
            }
            kase Op::POP_CC: {
                POP2(cc, ret);
                vm.cc = cc.ptr;
                PUSH(ret);
            }
            kase Op::CALLC: {
                FETCH_VALUE(u32, num_args);
                if (vm.sp - vm.bp < num_args + 1) {
                    return ExecutionError::TOO_MANY_ARGUMENTS;
                }
                std::swap(vm.stack[vm.sp - num_args - 1].ptr, vm.cc);
                // all pointers we create are safe to dereference
                u32 offset = *(u32 *)vm.cc;
                if (vm.rsp >= vm.rstack_top) return ExecutionError::STACK_OVERFLOW;
                auto &entry = vm.rstack[vm.rsp++];
                entry.ip = vm.ip;
                entry.fp = vm.fp;
                entry.lp = vm.lp;
                entry.bp = vm.bp;
                vm.ip = offset;
            }
            kase Op::PATT_FUN: {
                POP(x);
                PUSH_NUM_ASSUME_BOXED(Bclosure_tag_patt(x.ptr));
            }
            kase Op::PATT_SEXP: {
                POP(x);
                PUSH_NUM_ASSUME_BOXED(Bsexp_tag_patt(x.ptr));
            }
            kase Op::PATT_STRING: {
                POP(x);
                PUSH_NUM_ASSUME_BOXED(Bstring_tag_patt(x.ptr));
            }
            kase Op::PATT_ARRAY: {
                POP(x);
                PUSH_NUM_ASSUME_BOXED(Barray_tag_patt(x.ptr));
            }
            kase Op::PATT_REF: {
                POP(x);
                PUSH_NUM_ASSUME_BOXED(Bboxed_patt(x.ptr));
            }
            kase Op::PATT_VAL: {
                POP(x);
                PUSH_NUM_ASSUME_BOXED(Bunboxed_patt(x.ptr));
            }
            kase Op::PATT_STR: {
                POP2(x, y);
                PUSH_NUM_ASSUME_BOXED(Bstring_patt(x.ptr, y.ptr));
            }
            kase Op::PATT_ARR: {
                POP(x);
                FETCH_VALUE(u32, n);
                PUSH_NUM_ASSUME_BOXED(Barray_patt(x.ptr, BOX((aint)n)));
            }
            otherwise:
                throw std::runtime_error("Opcode not supported");
            }
        }

#undef ESCAPE
#undef POP
#undef POP2
#undef POP_NUM
#undef POP2_NUM
#undef PUSH_RAW
#undef PUSH_PTR
#undef PUSH_NUM_ASSUME_BOXED
#undef PUSH_NUM
#undef FETCH_OP
#undef FETCH_VALUE
    }

    u32 vm_get_line(Vm &vm) {
        auto it = std::lower_bound(vm.line_mapping.begin(), vm.line_mapping.end(),
            vm.ip,
            [](const auto &lhs, const auto &rhs) { return lhs.first < rhs; });
        if (it != vm.line_mapping.end() && it->first == vm.ip) {
            return it->second;
        }
        return 0;
    }

    ExecutionError vm_run(Vm &vm, const std::string &fn_name, const std::vector<Value> &args, bool trace = false) {
        if (!vm.global_functions.contains(fn_name)) {
            return ExecutionError::NAME_NOT_FOUND;
        }
        u32 offset = vm.global_functions.at(fn_name);
        vm.ip = offset;
        vm.rsp = 1;
        vm.sp = vm.globals_size;
        vm.lp = vm.globals_size;
        vm.fp = vm.globals_size;
        vm.rstack[0] = { .ip = 0, .fp = vm.globals_size, .lp = vm.globals_size };
        for (auto arg : args) {
            vm.stack[vm.sp++].number = arg.number;
        }
        return vm_continue(vm, trace);
    }
}


i32 app_execute(const char *bytecode_filename, bool trace = false) {
    __init();
    auto [guard, bc] = el::bytecode_from_file(bytecode_filename);
    if (trace) {
        el::dump_bytecode(stdout, bc);
    }
    auto vm = il::build_vm(il::VmConfig{
        .filename = std::string(bytecode_filename),
        .stack_size = 16 * 4024,
        .rstack_size = 4096,
    }, bc);
    if (std::holds_alternative<std::vector<std::string>>(vm)) {
        for (auto &err : std::get<std::vector<std::string>>(vm)) {
            std::printf("%s\n", err.c_str());
        }
        return 1;
    }
    auto _ = std::move(guard);

    switch (il::vm_run(std::get<0>(vm), "main", {
        il::Value { .number = BOX(0), },
        il::Value { .number = BOX(0), },
    }, trace)) {
        case il::ExecutionError::END:
            __shutdown();
            return 0;
        kase il::ExecutionError::NAME_NOT_FOUND:
            std::printf("Name not found\n");
        kase il::ExecutionError::STACK_UNDERFLOW:
            std::printf("Stack underflow\n");
        kase il::ExecutionError::STACK_OVERFLOW:
            std::printf("Stack overflow\n");
        kase il::ExecutionError::INTEGER_EXPECTED:
            std::printf("Integer expected\n");
        kase il::ExecutionError::RETURN_STACK_OVERFLOW:
            std::printf("Return stack overflow\n");
        kase il::ExecutionError::LOCAL_SLOT_OUT_OF_BOUNDS:
            std::printf("Local slot out of bounds\n");
        kase il::ExecutionError::ARITHMETIC_ERROR:
            std::printf("Arithmetic error\n");
        kase il::ExecutionError::ARG_SLOT_OUT_OF_BOUNDS:
            std::printf("Argument slot out of bounds\n");
        kase il::ExecutionError::POINTER_EXPECTED:
            std::printf("Pointer expected\n");
        kase il::ExecutionError::TOO_MANY_ARGUMENTS:
            std::printf("Too many arguments for a function\n");
        kase il::ExecutionError::STACK_INCONSISTENT:
            std::printf("Inconsistent stack usage\n");
        case il::ExecutionError::NOT_IN_CLOSURE:
            std::printf("Attempt to access closure variables outside closure\n");
    }
    __shutdown();
    return 1;
}

i32 app_decompile(const char *bytecode_filename) {
    auto [guard, bc] = el::bytecode_from_file(bytecode_filename);
    dump_bytecode(stdout, bc);
    return 0;
}

void fuzzing_entrypoint() {
    __init();
    u32 bytecode_size = 0;
    if (fread(&bytecode_size, sizeof(bytecode_size), 1, stdin) != 1) {
        std::fprintf(stderr, "Failed to read bytecode size from stdin\n");
        return;
    }

    std::vector<u8> bytecode(bytecode_size);
    
    if (size_t bytes_read = fread(bytecode.data(), 1, bytecode_size, stdin); bytes_read != bytecode_size) {
        std::fprintf(stderr, "Failed to read complete bytecode: got %zu bytes, expected %u\n", 
                    bytes_read, bytecode_size);
        return;
    }

    try {
        el::Bytecode bc = el::bytecode_from_bytes(bytecode.data(), bytecode.size());
        
        if (auto errors = el::validate_bytecode_stage0(bc); !errors.empty()) {
            for (const auto& err : errors) {
                std::fprintf(stderr, "Bytecode validation error: %s\n", err.c_str());
            }
            return;
        }

        il::VmConfig config{
            .filename = "[fuzzing]",
            .stack_size = 16 * 1024 * 1024,
            .rstack_size = 1024 * 1024,
        };

        auto vm_result = il::build_vm(config, bc);
        if (std::holds_alternative<std::vector<std::string>>(vm_result)) {
            for (const auto& err : std::get<std::vector<std::string>>(vm_result)) {
                std::fprintf(stderr, "VM creation error: %s\n", err.c_str());
            }
            return;
        }

        auto& vm = std::get<il::Vm>(vm_result);
        
        if (auto error = il::vm_run(vm, "main", {}, true); error != il::ExecutionError::END) {
            std::fprintf(stderr, "VM execution failed with error code %d\n", static_cast<int>(error));
            std::exit(1);
        }
    } catch (const std::exception& e) {
        std::fprintf(stderr, "Error: %s\n", e.what());
        std::exit(1);
    }
}

i32 main(i32 argc, char *argv[]) try {
    if (argc < 2) {
        std::printf("Usage: %s [subcommand] <bytecode.bc>\n", argv[0]);
        return 1;
    }

    if (argc == 2) {
        if (argv[1] == std::string("fuzz")) {
            fuzzing_entrypoint();
            return 0;
        }
        return app_execute(argv[1]);
    } else if (argc == 3) {
        if (std::string("execute").starts_with(argv[1])) {
            return app_execute(argv[2]);
        } else if (std::string("trace").starts_with(argv[1])) {
            return app_execute(argv[2], true);
        } else if (std::string("decompile").starts_with(argv[1])) {
            return app_decompile(argv[2]);
        } else {
            std::printf("Unknown subcommand: %s", argv[1]);
            return 1;
        }
    }
} catch (const std::runtime_error &e) {
    std::printf("%s\n", e.what());
    return 1;
}
