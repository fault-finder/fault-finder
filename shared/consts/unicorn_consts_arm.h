#ifndef UNICORN_CONSTS_ARM_H_INCLUDED
#define UNICORN_CONSTS_ARM_H_INCLUDED

uint64_t uc_reg_from_int_arm(uint64_t index);
uint64_t register_int_from_name_arm(const char* reg_name);
const char* register_name_from_int_arm(uint64_t index);
uint64_t uc_cpu_from_name_arm(const char* cpu_name);

#endif