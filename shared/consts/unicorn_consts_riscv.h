#ifndef UNICORN_CONSTS_RISCV_H_INCLUDED
#define UNICORN_CONSTS_RISCV_H_INCLUDED

uint64_t uc_reg_from_int_riscv(uint64_t index);
uint64_t register_int_from_name_riscv(const char* reg_name);
const char* register_name_from_int_riscv(uint64_t index);
uint64_t uc_cpu_from_name_riscv(const char* cpu_name);

#endif