#include <string.h>
#include <stdbool.h>
#include <unicorn/unicorn.h>
#include "../utils.h"
#include "../unicorn_consts.h"
#include "../configuration.h"
#include "unicorn_consts_x86.h"



uint64_t uc_cpu_from_name_x86(const char* cpu_name)
{
    static unicorn_const_t const cpu_array[]=
    {  
        {"QEMU64",UC_CPU_X86_QEMU64},{"PHENOM",UC_CPU_X86_PHENOM},{"CORE2DUO",UC_CPU_X86_CORE2DUO},{"KVM64",UC_CPU_X86_KVM64},{"QEMU32",UC_CPU_X86_QEMU32},{"KVM32",UC_CPU_X86_KVM32},{"COREDUO",UC_CPU_X86_COREDUO},{"486",UC_CPU_X86_486},{"PENTIUM",UC_CPU_X86_PENTIUM},{"PENTIUM2",UC_CPU_X86_PENTIUM2},{"PENTIUM3",UC_CPU_X86_PENTIUM3},{"ATHLON",UC_CPU_X86_ATHLON},{"N270",UC_CPU_X86_N270},{"CONROE",UC_CPU_X86_CONROE},{"PENRYN",UC_CPU_X86_PENRYN},{"NEHALEM",UC_CPU_X86_NEHALEM},{"WESTMERE",UC_CPU_X86_WESTMERE},{"SANDYBRIDGE",UC_CPU_X86_SANDYBRIDGE},{"IVYBRIDGE",UC_CPU_X86_IVYBRIDGE},{"HASWELL",UC_CPU_X86_HASWELL},{"BROADWELL",UC_CPU_X86_BROADWELL},{"SKYLAKE_CLIENT",UC_CPU_X86_SKYLAKE_CLIENT},{"SKYLAKE_SERVER",UC_CPU_X86_SKYLAKE_SERVER},{"CASCADELAKE_SERVER",UC_CPU_X86_CASCADELAKE_SERVER},{"COOPERLAKE",UC_CPU_X86_COOPERLAKE},{"ICELAKE_CLIENT",UC_CPU_X86_ICELAKE_CLIENT},{"ICELAKE_SERVER",UC_CPU_X86_ICELAKE_SERVER},{"DENVERTON",UC_CPU_X86_DENVERTON},{"SNOWRIDGE",UC_CPU_X86_SNOWRIDGE},{"KNIGHTSMILL",UC_CPU_X86_KNIGHTSMILL},{"OPTERON_G1",UC_CPU_X86_OPTERON_G1},{"OPTERON_G2",UC_CPU_X86_OPTERON_G2},{"OPTERON_G3",UC_CPU_X86_OPTERON_G3},{"OPTERON_G4",UC_CPU_X86_OPTERON_G4},{"OPTERON_G5",UC_CPU_X86_OPTERON_G5},{"EPYC",UC_CPU_X86_EPYC},{"DHYANA",UC_CPU_X86_DHYANA},{"EPYC_ROME",UC_CPU_X86_EPYC_ROME}
    };

    const int numEntries=sizeof(cpu_array) / sizeof(cpu_array[0]);
    for (int i=0;i<numEntries;i++)
    {
        if (strcasecmp(cpu_name,cpu_array[i].name) == 0)
        {
            return cpu_array[i].unicorn_value;
        }

    }
    fprintf(stderr, "Error %s is not a valid CPU for tricore.\n",cpu_name);
    fprintf(stderr, "Valid choices are:");
    for (int i=0;i<numEntries;i++)
    {
        fprintf(stderr, "%s ",cpu_array[i].name);
    }
    fprintf(stderr, "\n");
    my_exit(-1);
    return 666;  /// just here to keep the compiler happy. 
}


uint64_t uc_reg_from_int_x86(uint64_t index)
{
    static unicorn_const_t const x86_64_register_array[]=
    {
        {"AH",UC_X86_REG_AH},{"AL",UC_X86_REG_AL},{"AX",UC_X86_REG_AX},{"BH",UC_X86_REG_BH},{"BL",UC_X86_REG_BL},{"BP",UC_X86_REG_BP},{"BPL",UC_X86_REG_BPL},{"BX",UC_X86_REG_BX},{"CH",UC_X86_REG_CH},{"CL",UC_X86_REG_CL},{"CS",UC_X86_REG_CS},{"CX",UC_X86_REG_CX},{"DH",UC_X86_REG_DH},{"DI",UC_X86_REG_DI},{"DIL",UC_X86_REG_DIL},{"DL",UC_X86_REG_DL},{"DS",UC_X86_REG_DS},{"DX",UC_X86_REG_DX},{"EAX",UC_X86_REG_EAX},{"EBP",UC_X86_REG_EBP},{"EBX",UC_X86_REG_EBX},{"ECX",UC_X86_REG_ECX},{"EDI",UC_X86_REG_EDI},{"EDX",UC_X86_REG_EDX},{"EFLAGS",UC_X86_REG_EFLAGS},{"EIP",UC_X86_REG_EIP},{"ES",UC_X86_REG_ES},{"ESI",UC_X86_REG_ESI},{"ESP",UC_X86_REG_ESP},{"FPSW",UC_X86_REG_FPSW},{"FS",UC_X86_REG_FS},{"GS",UC_X86_REG_GS},{"IP",UC_X86_REG_IP},{"RAX",UC_X86_REG_RAX},{"RBP",UC_X86_REG_RBP},{"RBX",UC_X86_REG_RBX},{"RCX",UC_X86_REG_RCX},{"RDI",UC_X86_REG_RDI},{"RDX",UC_X86_REG_RDX},{"RIP",UC_X86_REG_RIP},{"RSI",UC_X86_REG_RSI},{"RSP",UC_X86_REG_RSP},{"SI",UC_X86_REG_SI},{"SIL",UC_X86_REG_SIL},{"SP",UC_X86_REG_SP},{"SPL",UC_X86_REG_SPL},{"SS",UC_X86_REG_SS},{"CR0",UC_X86_REG_CR0},{"CR1",UC_X86_REG_CR1},{"CR2",UC_X86_REG_CR2},{"CR3",UC_X86_REG_CR3},{"CR4",UC_X86_REG_CR4},{"CR8",UC_X86_REG_CR8},{"DR0",UC_X86_REG_DR0},{"DR1",UC_X86_REG_DR1},{"DR2",UC_X86_REG_DR2},{"DR3",UC_X86_REG_DR3},{"DR4",UC_X86_REG_DR4},{"DR5",UC_X86_REG_DR5},{"DR6",UC_X86_REG_DR6},{"DR7",UC_X86_REG_DR7},{"FP0",UC_X86_REG_FP0},{"FP1",UC_X86_REG_FP1},{"FP2",UC_X86_REG_FP2},{"FP3",UC_X86_REG_FP3},{"FP4",UC_X86_REG_FP4},{"FP5",UC_X86_REG_FP5},{"FP6",UC_X86_REG_FP6},{"FP7",UC_X86_REG_FP7},{"K0",UC_X86_REG_K0},{"K1",UC_X86_REG_K1},{"K2",UC_X86_REG_K2},{"K3",UC_X86_REG_K3},{"K4",UC_X86_REG_K4},{"K5",UC_X86_REG_K5},{"K6",UC_X86_REG_K6},{"K7",UC_X86_REG_K7},{"MM0",UC_X86_REG_MM0},{"MM1",UC_X86_REG_MM1},{"MM2",UC_X86_REG_MM2},{"MM3",UC_X86_REG_MM3},{"MM4",UC_X86_REG_MM4},{"MM5",UC_X86_REG_MM5},{"MM6",UC_X86_REG_MM6},{"MM7",UC_X86_REG_MM7},{"R8",UC_X86_REG_R8},{"R9",UC_X86_REG_R9},{"R10",UC_X86_REG_R10},{"R11",UC_X86_REG_R11},{"R12",UC_X86_REG_R12},{"R13",UC_X86_REG_R13},{"R14",UC_X86_REG_R14},{"R15",UC_X86_REG_R15},{"ST0",UC_X86_REG_ST0},{"ST1",UC_X86_REG_ST1},{"ST2",UC_X86_REG_ST2},{"ST3",UC_X86_REG_ST3},{"ST4",UC_X86_REG_ST4},{"ST5",UC_X86_REG_ST5},{"ST6",UC_X86_REG_ST6},{"ST7",UC_X86_REG_ST7},{"R8B",UC_X86_REG_R8B},{"R9B",UC_X86_REG_R9B},{"R10B",UC_X86_REG_R10B},{"R11B",UC_X86_REG_R11B},{"R12B",UC_X86_REG_R12B},{"R13B",UC_X86_REG_R13B},{"R14B",UC_X86_REG_R14B},{"R15B",UC_X86_REG_R15B},{"R8D",UC_X86_REG_R8D},{"R9D",UC_X86_REG_R9D},{"R10D",UC_X86_REG_R10D},{"R11D",UC_X86_REG_R11D},{"R12D",UC_X86_REG_R12D},{"R13D",UC_X86_REG_R13D},{"R14D",UC_X86_REG_R14D},{"R15D",UC_X86_REG_R15D},{"R8W",UC_X86_REG_R8W},{"R9W",UC_X86_REG_R9W},{"R10W",UC_X86_REG_R10W},{"R11W",UC_X86_REG_R11W},{"R12W",UC_X86_REG_R12W},{"R13W",UC_X86_REG_R13W},{"R14W",UC_X86_REG_R14W},{"R15W",UC_X86_REG_R15W}
    };

    const int numEntries=sizeof(x86_64_register_array) / sizeof(x86_64_register_array[0]);
    return index < numEntries ? x86_64_register_array[index].unicorn_value : UC_X86_REG_INVALID;
}

const char* register_name_from_int_x86(uint64_t index)
{
    static unicorn_const_t const x86_64_register_array[]={ {"AH",UC_X86_REG_AH},{"AL",UC_X86_REG_AL},{"AX",UC_X86_REG_AX},{"BH",UC_X86_REG_BH},{"BL",UC_X86_REG_BL},{"BP",UC_X86_REG_BP},{"BPL",UC_X86_REG_BPL},{"BX",UC_X86_REG_BX},{"CH",UC_X86_REG_CH},{"CL",UC_X86_REG_CL},{"CS",UC_X86_REG_CS},{"CX",UC_X86_REG_CX},{"DH",UC_X86_REG_DH},{"DI",UC_X86_REG_DI},{"DIL",UC_X86_REG_DIL},{"DL",UC_X86_REG_DL},{"DS",UC_X86_REG_DS},{"DX",UC_X86_REG_DX},{"EAX",UC_X86_REG_EAX},{"EBP",UC_X86_REG_EBP},{"EBX",UC_X86_REG_EBX},{"ECX",UC_X86_REG_ECX},{"EDI",UC_X86_REG_EDI},{"EDX",UC_X86_REG_EDX},{"EFLAGS",UC_X86_REG_EFLAGS},{"EIP",UC_X86_REG_EIP},{"ES",UC_X86_REG_ES},{"ESI",UC_X86_REG_ESI},{"ESP",UC_X86_REG_ESP},{"FPSW",UC_X86_REG_FPSW},{"FS",UC_X86_REG_FS},{"GS",UC_X86_REG_GS},{"IP",UC_X86_REG_IP},{"RAX",UC_X86_REG_RAX},{"RBP",UC_X86_REG_RBP},{"RBX",UC_X86_REG_RBX},{"RCX",UC_X86_REG_RCX},{"RDI",UC_X86_REG_RDI},{"RDX",UC_X86_REG_RDX},{"RIP",UC_X86_REG_RIP},{"RSI",UC_X86_REG_RSI},{"RSP",UC_X86_REG_RSP},{"SI",UC_X86_REG_SI},{"SIL",UC_X86_REG_SIL},{"SP",UC_X86_REG_SP},{"SPL",UC_X86_REG_SPL},{"SS",UC_X86_REG_SS},{"CR0",UC_X86_REG_CR0},{"CR1",UC_X86_REG_CR1},{"CR2",UC_X86_REG_CR2},{"CR3",UC_X86_REG_CR3},{"CR4",UC_X86_REG_CR4},{"CR8",UC_X86_REG_CR8},{"DR0",UC_X86_REG_DR0},{"DR1",UC_X86_REG_DR1},{"DR2",UC_X86_REG_DR2},{"DR3",UC_X86_REG_DR3},{"DR4",UC_X86_REG_DR4},{"DR5",UC_X86_REG_DR5},{"DR6",UC_X86_REG_DR6},{"DR7",UC_X86_REG_DR7},{"FP0",UC_X86_REG_FP0},{"FP1",UC_X86_REG_FP1},{"FP2",UC_X86_REG_FP2},{"FP3",UC_X86_REG_FP3},{"FP4",UC_X86_REG_FP4},{"FP5",UC_X86_REG_FP5},{"FP6",UC_X86_REG_FP6},{"FP7",UC_X86_REG_FP7},{"K0",UC_X86_REG_K0},{"K1",UC_X86_REG_K1},{"K2",UC_X86_REG_K2},{"K3",UC_X86_REG_K3},{"K4",UC_X86_REG_K4},{"K5",UC_X86_REG_K5},{"K6",UC_X86_REG_K6},{"K7",UC_X86_REG_K7},{"MM0",UC_X86_REG_MM0},{"MM1",UC_X86_REG_MM1},{"MM2",UC_X86_REG_MM2},{"MM3",UC_X86_REG_MM3},{"MM4",UC_X86_REG_MM4},{"MM5",UC_X86_REG_MM5},{"MM6",UC_X86_REG_MM6},{"MM7",UC_X86_REG_MM7},{"R8",UC_X86_REG_R8},{"R9",UC_X86_REG_R9},{"R10",UC_X86_REG_R10},{"R11",UC_X86_REG_R11},{"R12",UC_X86_REG_R12},{"R13",UC_X86_REG_R13},{"R14",UC_X86_REG_R14},{"R15",UC_X86_REG_R15},{"ST0",UC_X86_REG_ST0},{"ST1",UC_X86_REG_ST1},{"ST2",UC_X86_REG_ST2},{"ST3",UC_X86_REG_ST3},{"ST4",UC_X86_REG_ST4},{"ST5",UC_X86_REG_ST5},{"ST6",UC_X86_REG_ST6},{"ST7",UC_X86_REG_ST7},{"R8B",UC_X86_REG_R8B},{"R9B",UC_X86_REG_R9B},{"R10B",UC_X86_REG_R10B},{"R11B",UC_X86_REG_R11B},{"R12B",UC_X86_REG_R12B},{"R13B",UC_X86_REG_R13B},{"R14B",UC_X86_REG_R14B},{"R15B",UC_X86_REG_R15B},{"R8D",UC_X86_REG_R8D},{"R9D",UC_X86_REG_R9D},{"R10D",UC_X86_REG_R10D},{"R11D",UC_X86_REG_R11D},{"R12D",UC_X86_REG_R12D},{"R13D",UC_X86_REG_R13D},{"R14D",UC_X86_REG_R14D},{"R15D",UC_X86_REG_R15D},{"R8W",UC_X86_REG_R8W},{"R9W",UC_X86_REG_R9W},{"R10W",UC_X86_REG_R10W},{"R11W",UC_X86_REG_R11W},{"R12W",UC_X86_REG_R12W},{"R13W",UC_X86_REG_R13W},{"R14W",UC_X86_REG_R14W},{"R15W",UC_X86_REG_R15W}};

    const int numEntries=sizeof(x86_64_register_array) / sizeof(x86_64_register_array[0]);
    return index < numEntries ? x86_64_register_array[index].name : "Invalid";
}


uint64_t register_int_from_name_x86(const char* reg_name)
{
    for (int i=0;i<MAX_REGISTERS;i++)
    {
        if (strcasecmp(reg_name,register_name_from_int_x86(i)) == 0)
        {
            return i;
        }
    }
    fprintf(stderr, "Error %s is not a valid register for x86.\n",reg_name);
    fprintf(stderr, "Valid choices are:");
    for (int i=0;i<MAX_REGISTERS;i++)
    {
        fprintf(stderr, "%s ",register_name_from_int_x86(i));
    }
    fprintf(stderr, "\n");
    my_exit(-1);
    return 666;  /// just here to keep the compiler happy. 
}
