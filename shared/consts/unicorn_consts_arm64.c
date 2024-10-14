#include <string.h>
#include <stdbool.h>
#include <unicorn/unicorn.h>
#include "../utils.h"
#include "../unicorn_consts.h"
#include "../configuration.h"
#include "unicorn_consts_arm64.h"

uint64_t uc_cpu_from_name_arm64(const char* cpu_name)
{
    static unicorn_const_t const cpu_array[]=
    {  
        {"ARM64_A57",UC_CPU_ARM64_A57},{"ARM64_A53",UC_CPU_ARM64_A53},{"ARM64_A72",UC_CPU_ARM64_A72},{"ARM64_MAX",UC_CPU_ARM64_MAX}
    };

    const int numEntries=sizeof(cpu_array) / sizeof(cpu_array[0]);
    for (int i=0;i<numEntries;i++)
    {
        if (strcasecmp(cpu_name,cpu_array[i].name) == 0)
        {
            return cpu_array[i].unicorn_value;
        }
    }
    fprintf(stderr, "Error %s is not a valid CPU for arm64.\n",cpu_name);
    fprintf(stderr, "Valid choices are:");
    for (int i=0;i<numEntries;i++)
    {
        fprintf(stderr, "%s ",cpu_array[i].name);
    }
    fprintf(stderr, "\n");
    my_exit(-1);
    return 666;  /// just here to keep the compiler happy. 
}

uint64_t uc_reg_from_int_arm64(uint64_t index)
{
    static unicorn_const_t const register_array[]=
    {  
        {"X29",UC_ARM64_REG_X29},{"X30",UC_ARM64_REG_X30},{"NZCV",UC_ARM64_REG_NZCV},{"SP",UC_ARM64_REG_SP},{"WSP",UC_ARM64_REG_WSP},{"WZR",UC_ARM64_REG_WZR},{"XZR",UC_ARM64_REG_XZR},{"S0",UC_ARM64_REG_S0},{"S1",UC_ARM64_REG_S1},{"S2",UC_ARM64_REG_S2},{"S3",UC_ARM64_REG_S3},{"S4",UC_ARM64_REG_S4},{"S5",UC_ARM64_REG_S5},{"S6",UC_ARM64_REG_S6},{"S7",UC_ARM64_REG_S7},{"S8",UC_ARM64_REG_S8},{"S9",UC_ARM64_REG_S9},{"S10",UC_ARM64_REG_S10},{"S11",UC_ARM64_REG_S11},{"S12",UC_ARM64_REG_S12},{"S13",UC_ARM64_REG_S13},{"S14",UC_ARM64_REG_S14},{"S15",UC_ARM64_REG_S15},{"S16",UC_ARM64_REG_S16},{"S17",UC_ARM64_REG_S17},{"S18",UC_ARM64_REG_S18},{"S19",UC_ARM64_REG_S19},{"S20",UC_ARM64_REG_S20},{"S21",UC_ARM64_REG_S21},{"S22",UC_ARM64_REG_S22},{"S23",UC_ARM64_REG_S23},{"S24",UC_ARM64_REG_S24},{"S25",UC_ARM64_REG_S25},{"S26",UC_ARM64_REG_S26},{"S27",UC_ARM64_REG_S27},{"S28",UC_ARM64_REG_S28},{"S29",UC_ARM64_REG_S29},{"S30",UC_ARM64_REG_S30},{"S31",UC_ARM64_REG_S31},{"W0",UC_ARM64_REG_W0},{"W1",UC_ARM64_REG_W1},{"W2",UC_ARM64_REG_W2},{"W3",UC_ARM64_REG_W3},{"W4",UC_ARM64_REG_W4},{"W5",UC_ARM64_REG_W5},{"W6",UC_ARM64_REG_W6},{"W7",UC_ARM64_REG_W7},{"W8",UC_ARM64_REG_W8},{"W9",UC_ARM64_REG_W9},{"W10",UC_ARM64_REG_W10},{"W11",UC_ARM64_REG_W11},{"W12",UC_ARM64_REG_W12},{"W13",UC_ARM64_REG_W13},{"W14",UC_ARM64_REG_W14},{"W15",UC_ARM64_REG_W15},{"W16",UC_ARM64_REG_W16},{"W17",UC_ARM64_REG_W17},{"W18",UC_ARM64_REG_W18},{"W19",UC_ARM64_REG_W19},{"W20",UC_ARM64_REG_W20},{"W21",UC_ARM64_REG_W21},{"W22",UC_ARM64_REG_W22},{"W23",UC_ARM64_REG_W23},{"W24",UC_ARM64_REG_W24},{"W25",UC_ARM64_REG_W25},{"W26",UC_ARM64_REG_W26},{"W27",UC_ARM64_REG_W27},{"W28",UC_ARM64_REG_W28},{"W29",UC_ARM64_REG_W29},{"W30",UC_ARM64_REG_W30},{"X0",UC_ARM64_REG_X0},{"X1",UC_ARM64_REG_X1},{"X2",UC_ARM64_REG_X2},{"X3",UC_ARM64_REG_X3},{"X4",UC_ARM64_REG_X4},{"X5",UC_ARM64_REG_X5},{"X6",UC_ARM64_REG_X6},{"X7",UC_ARM64_REG_X7},{"X8",UC_ARM64_REG_X8},{"X9",UC_ARM64_REG_X9},{"X10",UC_ARM64_REG_X10},{"X11",UC_ARM64_REG_X11},{"X12",UC_ARM64_REG_X12},{"X13",UC_ARM64_REG_X13},{"X14",UC_ARM64_REG_X14},{"X15",UC_ARM64_REG_X15},{"X16",UC_ARM64_REG_X16},{"X17",UC_ARM64_REG_X17},{"X18",UC_ARM64_REG_X18},{"X19",UC_ARM64_REG_X19},{"X20",UC_ARM64_REG_X20},{"X21",UC_ARM64_REG_X21},{"X22",UC_ARM64_REG_X22},{"X23",UC_ARM64_REG_X23},{"X24",UC_ARM64_REG_X24},{"X25",UC_ARM64_REG_X25},{"X26",UC_ARM64_REG_X26},{"X27",UC_ARM64_REG_X27},{"X28",UC_ARM64_REG_X28},{"PC",UC_ARM64_REG_PC}, {"CPACR_EL1",UC_ARM64_REG_CPACR_EL1},{"PSTATE",UC_ARM64_REG_PSTATE},{"CP_REG",UC_ARM64_REG_CP_REG}
    };

    /*  alias registers
    UC_ARM64_REG_IP0 = UC_ARM64_REG_X16,    UC_ARM64_REG_IP1 = UC_ARM64_REG_X17,
    UC_ARM64_REG_FP = UC_ARM64_REG_X29,    UC_ARM64_REG_LR = UC_ARM64_REG_X30,
    */

    const int numEntries=sizeof(register_array) / sizeof(register_array[0]);
    return index < numEntries ? register_array[index].unicorn_value : UC_ARM64_REG_INVALID;
}

const char* register_name_from_int_arm64(uint64_t index)
{
    static unicorn_const_t const register_array[]=
    {  
        {"X29",UC_ARM64_REG_X29},{"X30",UC_ARM64_REG_X30},{"NZCV",UC_ARM64_REG_NZCV},{"SP",UC_ARM64_REG_SP},{"WSP",UC_ARM64_REG_WSP},{"WZR",UC_ARM64_REG_WZR},{"XZR",UC_ARM64_REG_XZR},{"S0",UC_ARM64_REG_S0},{"S1",UC_ARM64_REG_S1},{"S2",UC_ARM64_REG_S2},{"S3",UC_ARM64_REG_S3},{"S4",UC_ARM64_REG_S4},{"S5",UC_ARM64_REG_S5},{"S6",UC_ARM64_REG_S6},{"S7",UC_ARM64_REG_S7},{"S8",UC_ARM64_REG_S8},{"S9",UC_ARM64_REG_S9},{"S10",UC_ARM64_REG_S10},{"S11",UC_ARM64_REG_S11},{"S12",UC_ARM64_REG_S12},{"S13",UC_ARM64_REG_S13},{"S14",UC_ARM64_REG_S14},{"S15",UC_ARM64_REG_S15},{"S16",UC_ARM64_REG_S16},{"S17",UC_ARM64_REG_S17},{"S18",UC_ARM64_REG_S18},{"S19",UC_ARM64_REG_S19},{"S20",UC_ARM64_REG_S20},{"S21",UC_ARM64_REG_S21},{"S22",UC_ARM64_REG_S22},{"S23",UC_ARM64_REG_S23},{"S24",UC_ARM64_REG_S24},{"S25",UC_ARM64_REG_S25},{"S26",UC_ARM64_REG_S26},{"S27",UC_ARM64_REG_S27},{"S28",UC_ARM64_REG_S28},{"S29",UC_ARM64_REG_S29},{"S30",UC_ARM64_REG_S30},{"S31",UC_ARM64_REG_S31},{"W0",UC_ARM64_REG_W0},{"W1",UC_ARM64_REG_W1},{"W2",UC_ARM64_REG_W2},{"W3",UC_ARM64_REG_W3},{"W4",UC_ARM64_REG_W4},{"W5",UC_ARM64_REG_W5},{"W6",UC_ARM64_REG_W6},{"W7",UC_ARM64_REG_W7},{"W8",UC_ARM64_REG_W8},{"W9",UC_ARM64_REG_W9},{"W10",UC_ARM64_REG_W10},{"W11",UC_ARM64_REG_W11},{"W12",UC_ARM64_REG_W12},{"W13",UC_ARM64_REG_W13},{"W14",UC_ARM64_REG_W14},{"W15",UC_ARM64_REG_W15},{"W16",UC_ARM64_REG_W16},{"W17",UC_ARM64_REG_W17},{"W18",UC_ARM64_REG_W18},{"W19",UC_ARM64_REG_W19},{"W20",UC_ARM64_REG_W20},{"W21",UC_ARM64_REG_W21},{"W22",UC_ARM64_REG_W22},{"W23",UC_ARM64_REG_W23},{"W24",UC_ARM64_REG_W24},{"W25",UC_ARM64_REG_W25},{"W26",UC_ARM64_REG_W26},{"W27",UC_ARM64_REG_W27},{"W28",UC_ARM64_REG_W28},{"W29",UC_ARM64_REG_W29},{"W30",UC_ARM64_REG_W30},{"X0",UC_ARM64_REG_X0},{"X1",UC_ARM64_REG_X1},{"X2",UC_ARM64_REG_X2},{"X3",UC_ARM64_REG_X3},{"X4",UC_ARM64_REG_X4},{"X5",UC_ARM64_REG_X5},{"X6",UC_ARM64_REG_X6},{"X7",UC_ARM64_REG_X7},{"X8",UC_ARM64_REG_X8},{"X9",UC_ARM64_REG_X9},{"X10",UC_ARM64_REG_X10},{"X11",UC_ARM64_REG_X11},{"X12",UC_ARM64_REG_X12},{"X13",UC_ARM64_REG_X13},{"X14",UC_ARM64_REG_X14},{"X15",UC_ARM64_REG_X15},{"X16",UC_ARM64_REG_X16},{"X17",UC_ARM64_REG_X17},{"X18",UC_ARM64_REG_X18},{"X19",UC_ARM64_REG_X19},{"X20",UC_ARM64_REG_X20},{"X21",UC_ARM64_REG_X21},{"X22",UC_ARM64_REG_X22},{"X23",UC_ARM64_REG_X23},{"X24",UC_ARM64_REG_X24},{"X25",UC_ARM64_REG_X25},{"X26",UC_ARM64_REG_X26},{"X27",UC_ARM64_REG_X27},{"X28",UC_ARM64_REG_X28},{"PC",UC_ARM64_REG_PC}, {"CPACR_EL1",UC_ARM64_REG_CPACR_EL1},{"PSTATE",UC_ARM64_REG_PSTATE},{"CP_REG",UC_ARM64_REG_CP_REG}
    };

    const int numEntries=sizeof(register_array) / sizeof(register_array[0]);
    return index < numEntries ? register_array[index].name : "Invalid";
}


/**********************************************
 **** getting the integers from the name   ****
 **********************************************/
uint64_t register_int_from_name_arm64(const char* reg_name)
{
    for (int i=0;i<MAX_REGISTERS;i++)
    {
        if (strcasecmp(reg_name,register_name_from_int_arm64(i)) == 0)
        {
            return i;
        }
    }
    fprintf(stderr, "Error %s is not a valid register for arm64.\n",reg_name);
    fprintf(stderr, "Valid choices are:");
    for (int i=0;i<MAX_REGISTERS;i++)
    {
        fprintf(stderr, "%s ",register_name_from_int_arm64(i));
    }
    fprintf(stderr, "\n");
    my_exit(-1);
    return 666;  /// just here to keep the compiler happy. 
}