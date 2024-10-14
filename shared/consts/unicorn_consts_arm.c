#include <string.h>
#include <stdbool.h>
#include <unicorn/unicorn.h>
#include "../utils.h"
#include "../unicorn_consts.h"
#include "../configuration.h"
#include "unicorn_consts_arm.h"

    /*  alias registers
    UC_ARM_REG_R13 = UC_ARM_REG_SP,    UC_ARM_REG_R14 = UC_ARM_REG_LR,    UC_ARM_REG_R15 = UC_ARM_REG_PC,          UC_ARM_REG_SB = UC_ARM_REG_R9,
    UC_ARM_REG_SL = UC_ARM_REG_R10,    UC_ARM_REG_FP = UC_ARM_REG_R11,    UC_ARM_REG_IP = UC_ARM_REG_R12,*/


#define ARM_REG_ARRAY  {"APSR",UC_ARM_REG_APSR},{"APSR_NZCV",UC_ARM_REG_APSR_NZCV},{"CPSR",UC_ARM_REG_CPSR},{"FPEXC",UC_ARM_REG_FPEXC},{"FPINST",UC_ARM_REG_FPINST},{"FPSCR",UC_ARM_REG_FPSCR},{"FPSCR_NZCV",UC_ARM_REG_FPSCR_NZCV},{"FPSID",UC_ARM_REG_FPSID},{"ITSTATE",UC_ARM_REG_ITSTATE},{"LR",UC_ARM_REG_LR},{"PC",UC_ARM_REG_PC},{"SP",UC_ARM_REG_SP},{"SPSR",UC_ARM_REG_SPSR},{"D0",UC_ARM_REG_D0},{"D1",UC_ARM_REG_D1},{"D2",UC_ARM_REG_D2},{"D3",UC_ARM_REG_D3},{"D4",UC_ARM_REG_D4},{"D5",UC_ARM_REG_D5},{"D6",UC_ARM_REG_D6},{"D7",UC_ARM_REG_D7},{"D8",UC_ARM_REG_D8},{"D9",UC_ARM_REG_D9},{"D10",UC_ARM_REG_D10},{"D11",UC_ARM_REG_D11},{"D12",UC_ARM_REG_D12},{"D13",UC_ARM_REG_D13},{"D14",UC_ARM_REG_D14},{"D15",UC_ARM_REG_D15},{"D16",UC_ARM_REG_D16},{"D17",UC_ARM_REG_D17},{"D18",UC_ARM_REG_D18},{"D19",UC_ARM_REG_D19},{"D20",UC_ARM_REG_D20},{"D21",UC_ARM_REG_D21},{"D22",UC_ARM_REG_D22},{"D23",UC_ARM_REG_D23},{"D24",UC_ARM_REG_D24},{"D25",UC_ARM_REG_D25},{"D26",UC_ARM_REG_D26},{"D27",UC_ARM_REG_D27},{"D28",UC_ARM_REG_D28},{"D29",UC_ARM_REG_D29},{"D30",UC_ARM_REG_D30},{"D31",UC_ARM_REG_D31},{"FPINST2",UC_ARM_REG_FPINST2},{"MVFR0",UC_ARM_REG_MVFR0},{"MVFR1",UC_ARM_REG_MVFR1},{"MVFR2",UC_ARM_REG_MVFR2},{"Q0",UC_ARM_REG_Q0},{"Q1",UC_ARM_REG_Q1},{"Q2",UC_ARM_REG_Q2},{"Q3",UC_ARM_REG_Q3},{"Q4",UC_ARM_REG_Q4},{"Q5",UC_ARM_REG_Q5},{"Q6",UC_ARM_REG_Q6},{"Q7",UC_ARM_REG_Q7},{"Q8",UC_ARM_REG_Q8},{"Q9",UC_ARM_REG_Q9},{"Q10",UC_ARM_REG_Q10},{"Q11",UC_ARM_REG_Q11},{"Q12",UC_ARM_REG_Q12},{"Q13",UC_ARM_REG_Q13},{"Q14",UC_ARM_REG_Q14},{"Q15",UC_ARM_REG_Q15},{"R0",UC_ARM_REG_R0},{"R1",UC_ARM_REG_R1},{"R2",UC_ARM_REG_R2},{"R3",UC_ARM_REG_R3},{"R4",UC_ARM_REG_R4},{"R5",UC_ARM_REG_R5},{"R6",UC_ARM_REG_R6},{"R7",UC_ARM_REG_R7},{"R8",UC_ARM_REG_R8},{"SB",UC_ARM_REG_SB},{"SL",UC_ARM_REG_SL},{"FP",UC_ARM_REG_FP},{"IP",UC_ARM_REG_IP},{"S0",UC_ARM_REG_S0},{"S1",UC_ARM_REG_S1},{"S2",UC_ARM_REG_S2},{"S3",UC_ARM_REG_S3},{"S4",UC_ARM_REG_S4},{"S5",UC_ARM_REG_S5},{"S6",UC_ARM_REG_S6},{"S7",UC_ARM_REG_S7},{"S8",UC_ARM_REG_S8},{"S9",UC_ARM_REG_S9},{"S10",UC_ARM_REG_S10},{"S11",UC_ARM_REG_S11},{"S12",UC_ARM_REG_S12},{"S13",UC_ARM_REG_S13},{"S14",UC_ARM_REG_S14},{"S15",UC_ARM_REG_S15},{"S16",UC_ARM_REG_S16},{"S17",UC_ARM_REG_S17},{"S18",UC_ARM_REG_S18},{"S19",UC_ARM_REG_S19},{"S20",UC_ARM_REG_S20},{"S21",UC_ARM_REG_S21},{"S22",UC_ARM_REG_S22},{"S23",UC_ARM_REG_S23},{"S24",UC_ARM_REG_S24},{"S25",UC_ARM_REG_S25},{"S26",UC_ARM_REG_S26},{"S27",UC_ARM_REG_S27},{"S28",UC_ARM_REG_S28},{"S29",UC_ARM_REG_S29},{"S30",UC_ARM_REG_S30},{"S31",UC_ARM_REG_S31},{"IPSR",UC_ARM_REG_IPSR},{"MSP",UC_ARM_REG_MSP},{"PSP",UC_ARM_REG_PSP},{"CONTROL",UC_ARM_REG_CONTROL},{"IAPSR",UC_ARM_REG_IAPSR},{"EAPSR",UC_ARM_REG_EAPSR},{"XPSR",UC_ARM_REG_XPSR},{"EPSR",UC_ARM_REG_EPSR},{"IEPSR",UC_ARM_REG_IEPSR},{"PRIMASK",UC_ARM_REG_PRIMASK},{"BASEPRI",UC_ARM_REG_BASEPRI},{"BASEPRI_MAX",UC_ARM_REG_BASEPRI_MAX},{"FAULTMASK",UC_ARM_REG_FAULTMASK}

uint64_t uc_cpu_from_name_arm(const char* cpu_name)
{
    static unicorn_const_t const cpu_array[]=
    {  
        {"926",UC_CPU_ARM_926},{"946",UC_CPU_ARM_946},{"1026",UC_CPU_ARM_1026},{"1136_R2",UC_CPU_ARM_1136_R2},{"1136",UC_CPU_ARM_1136},{"1176",UC_CPU_ARM_1176},{"11MPCORE",UC_CPU_ARM_11MPCORE},{"CORTEX_M0",UC_CPU_ARM_CORTEX_M0},{"CORTEX_M3",UC_CPU_ARM_CORTEX_M3},{"CORTEX_M4",UC_CPU_ARM_CORTEX_M4},{"CORTEX_M7",UC_CPU_ARM_CORTEX_M7},{"CORTEX_M33",UC_CPU_ARM_CORTEX_M33},{"CORTEX_R5",UC_CPU_ARM_CORTEX_R5},{"CORTEX_R5F",UC_CPU_ARM_CORTEX_R5F},{"CORTEX_A7",UC_CPU_ARM_CORTEX_A7},{"CORTEX_A8",UC_CPU_ARM_CORTEX_A8},{"CORTEX_A9",UC_CPU_ARM_CORTEX_A9},{"CORTEX_A15",UC_CPU_ARM_CORTEX_A15},{"TI925T",UC_CPU_ARM_TI925T},{"SA1100",UC_CPU_ARM_SA1100},{"SA1110",UC_CPU_ARM_SA1110},{"PXA250",UC_CPU_ARM_PXA250},{"PXA255",UC_CPU_ARM_PXA255},{"PXA260",UC_CPU_ARM_PXA260},{"PXA261",UC_CPU_ARM_PXA261},{"PXA262",UC_CPU_ARM_PXA262},{"PXA270",UC_CPU_ARM_PXA270},{"PXA270A0",UC_CPU_ARM_PXA270A0},{"PXA270A1",UC_CPU_ARM_PXA270A1},{"PXA270B0",UC_CPU_ARM_PXA270B0},{"PXA270B1",UC_CPU_ARM_PXA270B1},{"PXA270C0",UC_CPU_ARM_PXA270C0},{"PXA270C5",UC_CPU_ARM_PXA270C5},{"MAX",UC_CPU_ARM_MAX}
    };

    const int numEntries=sizeof(cpu_array) / sizeof(cpu_array[0]);
    for (int i=0;i<numEntries;i++)
    {
        if (strcasecmp(cpu_name,cpu_array[i].name) == 0)
        {
            return cpu_array[i].unicorn_value;
        }
    }
    fprintf(stderr, "Error %s is not a valid CPU for arm.\n",cpu_name);
    fprintf(stderr, "Valid choices are:");
    for (int i=0;i<numEntries;i++)
    {
        fprintf(stderr, "%s ",cpu_array[i].name);
    }
    fprintf(stderr, "\n");
    my_exit(-1);
    return 666;  /// just here to keep the compiler happy. 
}

uint64_t uc_reg_from_int_arm(uint64_t index)
{
    static unicorn_const_t const register_array[]={ ARM_REG_ARRAY };



    const int numEntries=sizeof(register_array) / sizeof(register_array[0]);
    return index < numEntries ? register_array[index].unicorn_value : UC_ARM_REG_INVALID;
}

const char* register_name_from_int_arm(uint64_t index)
{
    static unicorn_const_t const register_array[]={ ARM_REG_ARRAY };

    const int numEntries=sizeof(register_array) / sizeof(register_array[0]);
    return index < numEntries ? register_array[index].name : "Invalid";
}

/**********************************************
 **** getting the integers from the name   ****
 **********************************************/
uint64_t register_int_from_name_arm(const char* reg_name)
{
    for (int i=0;i<MAX_REGISTERS;i++)
    {
        if (strcasecmp(reg_name,register_name_from_int_arm(i)) == 0)
        {
            return i;
        }
    }
    fprintf(stderr, "Error %s is not a valid register for arm.\n",reg_name);
    fprintf(stderr, "Valid choices are:");
    for (int i=0;i<MAX_REGISTERS;i++)
    {
        fprintf(stderr, "%s ",register_name_from_int_arm(i));
    }
    fprintf(stderr, "\n");
    my_exit(-1);
    return 666;  /// just here to keep the compiler happy. 
}