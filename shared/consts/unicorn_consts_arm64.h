#ifndef UNICORN_CONSTS_ARM64_H_INCLUDED
#define UNICORN_CONSTS_ARM64_H_INCLUDED

    uint64_t uc_reg_from_int_arm64(uint64_t index);
    uint64_t register_int_from_name_arm64(const char* reg_name);
    const char* register_name_from_int_arm64(uint64_t index);
    uint64_t uc_cpu_from_name_arm64(const char* cpu_name);

#endif