#ifndef UNICORN_CONSTS_H_INCLUDED
#define UNICORN_CONSTS_H_INCLUDED

#define MY_CS_MODE_NONE 0xdead
#define MY_CS_ARCH_NONE 0xdead
#define MY_UC_CPU_ERR  0xdead

    typedef struct  _unicorn_const_t
    {
        char* name;
        uint64_t unicorn_value;
    } unicorn_const_t;

    /* not currently used */
    typedef struct  _unicorn_register_const_t
    {
        char* name;
        uint64_t unicorn_value;
        uint64_t bitmap_value;
    } unicorn_register_const_t;

    const char* register_name_from_int(uint64_t index);
    uint64_t register_int_from_name(const char* reg_name);
    uint64_t uc_reg_from_int(uint64_t index);
    void print_register_from_name(uc_engine* uc,FILE* fd,char* reg_name);

    uint64_t unicorn_arch_int_from_name(const char* arch_name);
    const char* unicorn_arch_name_from_int(uint64_t arch_int);

    uint64_t unicorn_mode_int_from_name(const char* arch_name);
    const char* unicorn_mode_name_from_int(uint64_t arch_int);

    uint64_t capstone_arch_int_from_name(const char* capstone_arch_name);
    const char* capstone_arch_name_from_int(uint64_t capstone_arch_int);

    uint64_t capstone_mode_int_from_name(const char* capstone_mode_name);
    const char* capstone_mode_name_from_int(uint64_t capstone_mode_int);
    
    uint64_t uc_cpu_from_name(const char* cpu_name);
#endif