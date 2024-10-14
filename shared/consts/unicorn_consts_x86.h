#ifndef UNICORN_CONSTS_X86_H_INCLUDED
#define UNICORN_CONSTS_X86_H_INCLUDED

    uint64_t uc_reg_from_int_x86(uint64_t index);
    uint64_t register_int_from_name_x86(const char* reg_name);
    const char* register_name_from_int_x86(uint64_t index);
    uint64_t uc_cpu_from_name_x86(const char* cpu_name);

#endif