#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include <unicorn/unicorn.h>
#include "utils.h"
#include "unicorn_consts.h"
#include "configuration.h"
#include <capstone/capstone.h>
#include "consts/unicorn_consts_arm.h"
#include "consts/unicorn_consts_arm64.h"
#include "consts/unicorn_consts_tricore.h"
#include "consts/unicorn_consts_riscv.h"
#include "consts/unicorn_consts_x86.h"
#include "consts/unicorn_consts_mips.h"
#include "consts/unicorn_consts_ppc.h"


static unicorn_const_t const ucc_arch[]={{"arm",UC_ARCH_ARM },{"arm64",UC_ARCH_ARM64},{"x86", UC_ARCH_X86},{"tricore", UC_ARCH_TRICORE},{"riscv",UC_ARCH_RISCV},{"mips",UC_ARCH_MIPS},{"ppc",UC_ARCH_PPC}};
static const size_t ucc_arch_size = sizeof(ucc_arch)/sizeof(ucc_arch[0]);

static unicorn_const_t const ucc_mode[]={{"16",UC_MODE_16 },{"32",UC_MODE_32},{"64", UC_MODE_64},{"ARM1176", UC_MODE_ARM1176},{"ARM946", UC_MODE_ARM946},{"ARM926", UC_MODE_ARM926},{"ARMBE8", UC_MODE_ARMBE8},{"big endian",UC_MODE_BIG_ENDIAN},{"little endian",UC_MODE_LITTLE_ENDIAN},{"MCLASS", UC_MODE_MCLASS},{"MICRO", UC_MODE_MICRO},{"mips32",UC_MODE_MIPS32},{"mips64",UC_MODE_MIPS32R6},{"mips3",UC_MODE_MIPS3},{"mips64",UC_MODE_MIPS64},{"ppc32",UC_MODE_PPC32},{"ppc64",UC_MODE_PPC64},{"qpx",UC_MODE_QPX},{"riscv32",UC_MODE_RISCV32},{"riscv64",UC_MODE_RISCV64},{"sparc32",UC_MODE_SPARC32},{"sparc64",UC_MODE_SPARC64},{"THUMB", UC_MODE_THUMB},{"V8",UC_MODE_V8},{"V9",UC_MODE_V9}};
static const size_t ucc_mode_size = sizeof(ucc_mode)/sizeof(ucc_mode[0]); 

static unicorn_const_t const cc_arch[]={{"arm",CS_ARCH_ARM},{"arm64",CS_ARCH_ARM64},{"mips",CS_ARCH_MIPS},{"x86",CS_ARCH_X86},{"ppc",CS_ARCH_PPC},{"sparc",CS_ARCH_SPARC},{"sysz",CS_ARCH_SYSZ},{"xcore",CS_ARCH_XCORE},{"m68K",CS_ARCH_M68K},{"TMS320C64X",CS_ARCH_TMS320C64X},{"M680X",CS_ARCH_M680X},{"evm",CS_ARCH_EVM},{"max",CS_ARCH_MAX},{"riscv",UC_ARCH_RISCV},
{"none",MY_CS_ARCH_NONE}};           
static const size_t cc_arch_size = sizeof(cc_arch)/sizeof(cc_arch[0]);

static unicorn_const_t const cc_mode[]={{"LITTLE_ENDIAN",CS_MODE_LITTLE_ENDIAN},{"ARM",CS_MODE_ARM},{"16",CS_MODE_16},{"32",CS_MODE_32},{"64",CS_MODE_64},{"THUMB",CS_MODE_THUMB},{"MCLASS",CS_MODE_MCLASS},{"V8",CS_MODE_V8},{"MICRO",CS_MODE_MICRO},{"MIPS3",CS_MODE_MIPS3},{"MIPS32R6",CS_MODE_MIPS32R6},{"MIPS2",CS_MODE_MIPS2},{"V9",CS_MODE_V9},{"QPX",CS_MODE_QPX},{"M68K_000",CS_MODE_M68K_000},{"M68K_010",CS_MODE_M68K_010},{"M68K_020",CS_MODE_M68K_020},{"M68K_030",CS_MODE_M68K_030},{"M68K_040",CS_MODE_M68K_040},{"M68K_060",CS_MODE_M68K_060},{"BIG_ENDIAN",CS_MODE_BIG_ENDIAN},{"MIPS32",CS_MODE_MIPS32},{"MIPS64",CS_MODE_MIPS64},{"M680X_6301",CS_MODE_M680X_6301},{"M680X_6309",CS_MODE_M680X_6309},{"M680X_6800",CS_MODE_M680X_6800},{"M680X_6801",CS_MODE_M680X_6801},{"M680X_6805",CS_MODE_M680X_6805},{"M680X_6808",CS_MODE_M680X_6808},{"M680X_6809",CS_MODE_M680X_6809},{"M680X_6811",CS_MODE_M680X_6811},{"M680X_CPU12",CS_MODE_M680X_CPU12},{"M680X_HCS08",CS_MODE_M680X_HCS08},{"none",MY_CS_MODE_NONE}};
static const size_t cc_mode_size = sizeof(cc_mode)/sizeof(cc_mode[0]);



const char* register_name_from_int(uint64_t index)
{
    switch (binary_file_details->my_uc_arch)
    {
        case UC_ARCH_X86:
            return register_name_from_int_x86(index);
        case UC_ARCH_ARM:
            return register_name_from_int_arm(index);
        case UC_ARCH_TRICORE:
            return register_name_from_int_tricore(index);
        case UC_ARCH_RISCV:
            return register_name_from_int_riscv(index);
        case UC_ARCH_MIPS:
            return register_name_from_int_mips(index);
        case UC_ARCH_PPC:
            return register_name_from_int_ppc(index);
        case UC_ARCH_ARM64:
            return register_name_from_int_arm64(index);
        default:
            fprintf(stderr, "Error. Cannot find register for architecture: %llu.\n",index);
            my_exit(-1);
    }
    return "";  /// just here to keep the compiler happy.
}

/********************************** ARCH ************************************/
uint64_t unicorn_arch_int_from_name(const char* unicorn_arch_name)
{
    for (size_t i=0;i<ucc_arch_size;i++)
    {
        if (strcasecmp(unicorn_arch_name,ucc_arch[i].name) == 0)
        {
            return ucc_arch[i].unicorn_value;
        }
    }
    fprintf(stderr, "Error. %s is not a valid architecture.\n",unicorn_arch_name);
    fprintf(stderr, "Valid architectures are: ");
    for (size_t i=0;i<ucc_arch_size;i++)
    {
        printf("%s ",ucc_arch[i].name);
    }
    printf("\n");
    my_exit(-1);
    return 666; //for compiler
}

const char* unicorn_arch_name_from_int(uint64_t unicorn_arch_int)
{
    for (size_t i=0;i<ucc_arch_size;i++)
    {
        if (ucc_arch[i].unicorn_value == unicorn_arch_int)
        {
            return ucc_arch[i].name;
        }
    }
    fprintf(stderr, "Error. %llu is not a valid architecture constant in unicorn.\n",unicorn_arch_int);
    my_exit(-1);
    return "Whoops"; //for compiler

}


/********************************** MODE ************************************/
uint64_t unicorn_mode_int_from_name(const char* unicorn_mode_name)
{
    for (size_t i=0;i<ucc_mode_size;i++)
    {
        if (strcasecmp(unicorn_mode_name,ucc_mode[i].name) == 0)
        {
            return ucc_mode[i].unicorn_value;
        }
    }
    fprintf(stderr, "Error. %s is not a valid mode.\n",unicorn_mode_name);
    fprintf(stderr, "Valid modes are: ");
    for (size_t i=0;i<ucc_mode_size;i++)
    {
        printf("%s ",ucc_mode[i].name);
    }
    printf("\n");
    my_exit(-1);
    return 666; //for compiler
}

const char* unicorn_mode_name_from_int(uint64_t unicorn_mode_int)
{
    for (size_t i=0;i<ucc_mode_size;i++)
    {
        if (ucc_mode[i].unicorn_value == unicorn_mode_int)
        {
            return ucc_mode[i].name;
        }
    }
    fprintf(stderr, "Error. %llu is not a valid mode constant in unicorn.\n",unicorn_mode_int);
    my_exit(-1);
    return "Whoops"; //for compiler
}


/********************************** CAPSTONE MODE ************************************/
uint64_t capstone_mode_int_from_name(const char* capstone_mode_name)
{
    for (size_t i=0;i<cc_mode_size;i++)
    {
        if (strcasecmp(capstone_mode_name,cc_mode[i].name) == 0)
        {
            return cc_mode[i].unicorn_value;
        }
    }
    fprintf(stderr, "Error. %s is not a valid capstone mode.\n",capstone_mode_name);
    fprintf(stderr, "Valid modes are: ");
    for (size_t i=0;i<cc_mode_size;i++)
    {
        printf("%s ",cc_mode[i].name);
    }
    printf("\n");
    my_exit(-1);
    return 666; //for compiler
}

const char* capstone_mode_name_from_int(uint64_t capstone_mode_int)
{
    for (size_t i=0;i<cc_mode_size;i++)
    {
        if (cc_mode[i].unicorn_value == capstone_mode_int)
        {
            return cc_mode[i].name;
        }
    }
    fprintf(stderr, "Error. %llu is not a valid mode constant in capstone.\n",capstone_mode_int);
    my_exit(-1);
    return "Whoops"; //for compiler
}

/********************************** CAPSTONE arch ************************************/
uint64_t capstone_arch_int_from_name(const char* capstone_arch_name)
{
    for (size_t i=0;i<cc_arch_size;i++)
    {
        if (strcasecmp(capstone_arch_name,cc_arch[i].name) == 0)
        {
            return cc_arch[i].unicorn_value;
        }
    }
    fprintf(stderr, "Error. %s is not a valid capstone arch.\n",capstone_arch_name);
    fprintf(stderr, "Valid capstone archs are: ");
    for (size_t i=0;i<cc_arch_size;i++)
    {
        printf("%s ",cc_arch[i].name);
    }
    printf("\n");
    my_exit(-1);
    return 666; //for compiler
}

const char* capstone_arch_name_from_int(uint64_t capstone_arch_int)
{
    for (size_t i=0;i<cc_arch_size;i++)
    {
        if (cc_arch[i].unicorn_value == capstone_arch_int)
        {
            return cc_arch[i].name;
        }
    }
    fprintf(stderr, "Error. %llu is not a valid arch constant in capstone.\n",capstone_arch_int);
    my_exit(-1);
    return "Whoops"; //for compiler
}

/**********************************************
 **** getting the integers from the int    ****
 **********************************************/
uint64_t register_int_from_name(const char* reg_name)
{
    switch (binary_file_details->my_uc_arch)
    {
    case UC_ARCH_ARM:
        return register_int_from_name_arm(reg_name);
    case UC_ARCH_X86:
            return register_int_from_name_x86(reg_name);
    case UC_ARCH_TRICORE:
        return register_int_from_name_tricore(reg_name);
    case UC_ARCH_RISCV:
        return register_int_from_name_riscv(reg_name);
    case UC_ARCH_MIPS:
        return register_int_from_name_mips(reg_name);
    case UC_ARCH_PPC:
        return register_int_from_name_ppc(reg_name);
    case UC_ARCH_ARM64:    
        fprintf(stderr, "Error. Not implemented.\n");
        my_exit(-1);
    default:
        fprintf(stderr, "Error. Cannot find register for architecture for register name: %s.\n",reg_name);
        my_exit(-1);
    }
    return 666;  /// just here to keep the compiler happy.
}

uint64_t uc_reg_from_int(uint64_t index)
{
    switch (binary_file_details->my_uc_arch)
    {
        case UC_ARCH_ARM:
            return uc_reg_from_int_arm(index);
        case UC_ARCH_X86:
            return uc_reg_from_int_x86(index);
        case UC_ARCH_TRICORE:
            return uc_reg_from_int_tricore(index);
        case UC_ARCH_RISCV:
            return uc_reg_from_int_riscv(index);
        case UC_ARCH_MIPS:
            return uc_reg_from_int_mips(index);
        case UC_ARCH_PPC:
            return uc_reg_from_int_ppc(index);
        case UC_ARCH_ARM64:    
            return uc_reg_from_int_arm64(index);
        default:
            fprintf(stderr, "Error. Cannot find register for architecture: %llu.\n",index);
            my_exit(-1);
    }
    return 666;  /// just here to keep the compiler happy.
}

uint64_t uc_cpu_from_name(const char* cpu_name)
{
    switch (binary_file_details->my_uc_arch)
    {
        case UC_ARCH_ARM:
            return uc_cpu_from_name_arm (cpu_name);
        case UC_ARCH_ARM64:    
            return uc_cpu_from_name_arm64(cpu_name);
        case UC_ARCH_X86:
            return uc_cpu_from_name_x86(cpu_name);
        case UC_ARCH_TRICORE:
            return uc_cpu_from_name_tricore(cpu_name);
        case UC_ARCH_RISCV:
            return uc_cpu_from_name_riscv(cpu_name);
        case UC_ARCH_MIPS:
            return uc_cpu_from_name_mips(cpu_name);
        case UC_ARCH_PPC:
            return uc_cpu_from_name_ppc(cpu_name);
        default:
            fprintf(stderr, "Error. Cannot find cpu for architecture: %s.\n",cpu_name);
            my_exit(-1);
    }
    return 666;  /// just here to keep the compiler happy.
}
