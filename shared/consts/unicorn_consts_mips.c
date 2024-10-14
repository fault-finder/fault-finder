#include <string.h>
#include <stdbool.h>
#include <unicorn/unicorn.h>
#include "../utils.h"
#include "../unicorn_consts.h"
#include "../configuration.h"
#include "unicorn_consts_mips.h"

uint64_t uc_cpu_from_name_mips(const char* cpu_name)
{
    static unicorn_const_t const cpu_array[]=
    {  
        {"4KC",UC_CPU_MIPS32_4KC},{"4KM",UC_CPU_MIPS32_4KM},{"4KECR1",UC_CPU_MIPS32_4KECR1},{"4KEMR1",UC_CPU_MIPS32_4KEMR1},{"4KEC",UC_CPU_MIPS32_4KEC},{"4KEM",UC_CPU_MIPS32_4KEM},{"24KC",UC_CPU_MIPS32_24KC},{"24KEC",UC_CPU_MIPS32_24KEC},{"24KF",UC_CPU_MIPS32_24KF},{"34KF",UC_CPU_MIPS32_34KF},{"74KF",UC_CPU_MIPS32_74KF},{"M14K",UC_CPU_MIPS32_M14K},{"M14KC",UC_CPU_MIPS32_M14KC},{"P5600",UC_CPU_MIPS32_P5600},{"MIPS32R6_GENERIC",UC_CPU_MIPS32_MIPS32R6_GENERIC},{"I7200",UC_CPU_MIPS32_I7200}
    };

    const int numEntries=sizeof(cpu_array) / sizeof(cpu_array[0]);
    for (int i=0;i<numEntries;i++)
    {
        if (strcasecmp(cpu_name,cpu_array[i].name) == 0)
        {
            return cpu_array[i].unicorn_value;
        }

    }
    fprintf(stderr, "Error %s is not a valid CPU for mips.\n",cpu_name);
    fprintf(stderr, "Valid choices are:");
    for (int i=0;i<numEntries;i++)
    {
        fprintf(stderr, "%s ",cpu_array[i].name);
    }
    fprintf(stderr, "\n");
    my_exit(-1);
    return 666;  /// just here to keep the compiler happy. 
}


/************************************************** uc_reg_from_int_mips and register_name_from_int_mips MUST MATCH ************************************/
uint64_t uc_reg_from_int_mips(uint64_t index)
{
    static unicorn_const_t const register_array[]={
        {"PC",UC_MIPS_REG_PC},{"0",UC_MIPS_REG_0},{"1",UC_MIPS_REG_1},{"2",UC_MIPS_REG_2},{"3",UC_MIPS_REG_3},{"4",UC_MIPS_REG_4},{"5",UC_MIPS_REG_5},{"6",UC_MIPS_REG_6},{"7",UC_MIPS_REG_7},{"8",UC_MIPS_REG_8},{"9",UC_MIPS_REG_9},{"10",UC_MIPS_REG_10},{"11",UC_MIPS_REG_11},{"12",UC_MIPS_REG_12},{"13",UC_MIPS_REG_13},{"14",UC_MIPS_REG_14},{"15",UC_MIPS_REG_15},{"16",UC_MIPS_REG_16},{"17",UC_MIPS_REG_17},{"18",UC_MIPS_REG_18},{"19",UC_MIPS_REG_19},{"20",UC_MIPS_REG_20},{"21",UC_MIPS_REG_21},{"22",UC_MIPS_REG_22},{"23",UC_MIPS_REG_23},{"24",UC_MIPS_REG_24},{"25",UC_MIPS_REG_25},{"26",UC_MIPS_REG_26},{"27",UC_MIPS_REG_27},{"28",UC_MIPS_REG_28},{"29",UC_MIPS_REG_29},{"30",UC_MIPS_REG_30},{"31",UC_MIPS_REG_31},{"DSPCCOND",UC_MIPS_REG_DSPCCOND},{"DSPCARRY",UC_MIPS_REG_DSPCARRY},{"DSPEFI",UC_MIPS_REG_DSPEFI},{"DSPOUTFLAG",UC_MIPS_REG_DSPOUTFLAG},{"DSPOUTFLAG16_19",UC_MIPS_REG_DSPOUTFLAG16_19},{"DSPOUTFLAG20",UC_MIPS_REG_DSPOUTFLAG20},{"DSPOUTFLAG21",UC_MIPS_REG_DSPOUTFLAG21},{"DSPOUTFLAG22",UC_MIPS_REG_DSPOUTFLAG22},{"DSPOUTFLAG23",UC_MIPS_REG_DSPOUTFLAG23},{"DSPPOS",UC_MIPS_REG_DSPPOS},{"DSPSCOUNT",UC_MIPS_REG_DSPSCOUNT},{"AC0",UC_MIPS_REG_AC0},{"AC1",UC_MIPS_REG_AC1},{"AC2",UC_MIPS_REG_AC2},{"AC3",UC_MIPS_REG_AC3},{"CC0",UC_MIPS_REG_CC0},{"CC1",UC_MIPS_REG_CC1},{"CC2",UC_MIPS_REG_CC2},{"CC3",UC_MIPS_REG_CC3},{"CC4",UC_MIPS_REG_CC4},{"CC5",UC_MIPS_REG_CC5},{"CC6",UC_MIPS_REG_CC6},{"CC7",UC_MIPS_REG_CC7},{"F0",UC_MIPS_REG_F0},{"F1",UC_MIPS_REG_F1},{"F2",UC_MIPS_REG_F2},{"F3",UC_MIPS_REG_F3},{"F4",UC_MIPS_REG_F4},{"F5",UC_MIPS_REG_F5},{"F6",UC_MIPS_REG_F6},{"F7",UC_MIPS_REG_F7},{"F8",UC_MIPS_REG_F8},{"F9",UC_MIPS_REG_F9},{"F10",UC_MIPS_REG_F10},{"F11",UC_MIPS_REG_F11},{"F12",UC_MIPS_REG_F12},{"F13",UC_MIPS_REG_F13},{"F14",UC_MIPS_REG_F14},{"F15",UC_MIPS_REG_F15},{"F16",UC_MIPS_REG_F16},{"F17",UC_MIPS_REG_F17},{"F18",UC_MIPS_REG_F18},{"F19",UC_MIPS_REG_F19},{"F20",UC_MIPS_REG_F20},{"F21",UC_MIPS_REG_F21},{"F22",UC_MIPS_REG_F22},{"F23",UC_MIPS_REG_F23},{"F24",UC_MIPS_REG_F24},{"F25",UC_MIPS_REG_F25},{"F26",UC_MIPS_REG_F26},{"F27",UC_MIPS_REG_F27},{"F28",UC_MIPS_REG_F28},{"F29",UC_MIPS_REG_F29},{"F30",UC_MIPS_REG_F30},{"F31",UC_MIPS_REG_F31},{"FCC0",UC_MIPS_REG_FCC0},{"FCC1",UC_MIPS_REG_FCC1},{"FCC2",UC_MIPS_REG_FCC2},{"FCC3",UC_MIPS_REG_FCC3},{"FCC4",UC_MIPS_REG_FCC4},{"FCC5",UC_MIPS_REG_FCC5},{"FCC6",UC_MIPS_REG_FCC6},{"FCC7",UC_MIPS_REG_FCC7},{"W0",UC_MIPS_REG_W0},{"W1",UC_MIPS_REG_W1},{"W2",UC_MIPS_REG_W2},{"W3",UC_MIPS_REG_W3},{"W4",UC_MIPS_REG_W4},{"W5",UC_MIPS_REG_W5},{"W6",UC_MIPS_REG_W6},{"W7",UC_MIPS_REG_W7},{"W8",UC_MIPS_REG_W8},{"W9",UC_MIPS_REG_W9},{"W10",UC_MIPS_REG_W10},{"W11",UC_MIPS_REG_W11},{"W12",UC_MIPS_REG_W12},{"W13",UC_MIPS_REG_W13},{"W14",UC_MIPS_REG_W14},{"W15",UC_MIPS_REG_W15},{"W16",UC_MIPS_REG_W16},{"W17",UC_MIPS_REG_W17},{"W18",UC_MIPS_REG_W18},{"W19",UC_MIPS_REG_W19},{"W20",UC_MIPS_REG_W20},{"W21",UC_MIPS_REG_W21},{"W22",UC_MIPS_REG_W22},{"W23",UC_MIPS_REG_W23},{"W24",UC_MIPS_REG_W24},{"W25",UC_MIPS_REG_W25},{"W26",UC_MIPS_REG_W26},{"W27",UC_MIPS_REG_W27},{"W28",UC_MIPS_REG_W28},{"W29",UC_MIPS_REG_W29},{"W30",UC_MIPS_REG_W30},{"W31",UC_MIPS_REG_W31}
    };

    const int numEntries=sizeof(register_array) / sizeof(register_array[0]);
    return index < numEntries ? register_array[index].unicorn_value : UC_MIPS_REG_INVALID;

        /* alias registers
    UC_MIPS_REG_ZERO = UC_MIPS_REG_0,   UC_MIPS_REG_AT = UC_MIPS_REG_1,    UC_MIPS_REG_V0 = UC_MIPS_REG_2,     UC_MIPS_REG_V1 = UC_MIPS_REG_3,
    UC_MIPS_REG_A0 = UC_MIPS_REG_4,     UC_MIPS_REG_A1 = UC_MIPS_REG_5,    UC_MIPS_REG_A2 = UC_MIPS_REG_6,     UC_MIPS_REG_A3 = UC_MIPS_REG_7,
    UC_MIPS_REG_T0 = UC_MIPS_REG_8,     UC_MIPS_REG_T1 = UC_MIPS_REG_9,    UC_MIPS_REG_T2 = UC_MIPS_REG_10,    UC_MIPS_REG_T3 = UC_MIPS_REG_11,
    UC_MIPS_REG_T4 = UC_MIPS_REG_12,    UC_MIPS_REG_T5 = UC_MIPS_REG_13,   UC_MIPS_REG_T6 = UC_MIPS_REG_14,    UC_MIPS_REG_T7 = UC_MIPS_REG_15,
    UC_MIPS_REG_S0 = UC_MIPS_REG_16,    UC_MIPS_REG_S1 = UC_MIPS_REG_17,   UC_MIPS_REG_S2 = UC_MIPS_REG_18,    UC_MIPS_REG_S3 = UC_MIPS_REG_19,
    UC_MIPS_REG_S4 = UC_MIPS_REG_20,    UC_MIPS_REG_S5 = UC_MIPS_REG_21,   UC_MIPS_REG_S6 = UC_MIPS_REG_22,    UC_MIPS_REG_S7 = UC_MIPS_REG_23,
    UC_MIPS_REG_T8 = UC_MIPS_REG_24,    UC_MIPS_REG_T9 = UC_MIPS_REG_25,   UC_MIPS_REG_K0 = UC_MIPS_REG_26,    UC_MIPS_REG_K1 = UC_MIPS_REG_27,
    UC_MIPS_REG_GP = UC_MIPS_REG_28,    UC_MIPS_REG_SP = UC_MIPS_REG_29,   UC_MIPS_REG_FP = UC_MIPS_REG_30,    UC_MIPS_REG_S8 = UC_MIPS_REG_30,
    UC_MIPS_REG_RA = UC_MIPS_REG_31,

    UC_MIPS_REG_HI0 = UC_MIPS_REG_AC0,    UC_MIPS_REG_HI1 = UC_MIPS_REG_AC1,
    UC_MIPS_REG_HI2 = UC_MIPS_REG_AC2,    UC_MIPS_REG_HI3 = UC_MIPS_REG_AC3,

    UC_MIPS_REG_LO0 = UC_MIPS_REG_HI0,    UC_MIPS_REG_LO1 = UC_MIPS_REG_HI1,
    UC_MIPS_REG_LO2 = UC_MIPS_REG_HI2,    UC_MIPS_REG_LO3 = UC_MIPS_REG_HI3 */ 
}
const char* register_name_from_int_mips(uint64_t index)
{
    static unicorn_const_t const register_array[]={
        {"PC",UC_MIPS_REG_PC},{"0",UC_MIPS_REG_0},{"1",UC_MIPS_REG_1},{"2",UC_MIPS_REG_2},{"3",UC_MIPS_REG_3},{"4",UC_MIPS_REG_4},{"5",UC_MIPS_REG_5},{"6",UC_MIPS_REG_6},{"7",UC_MIPS_REG_7},{"8",UC_MIPS_REG_8},{"9",UC_MIPS_REG_9},{"10",UC_MIPS_REG_10},{"11",UC_MIPS_REG_11},{"12",UC_MIPS_REG_12},{"13",UC_MIPS_REG_13},{"14",UC_MIPS_REG_14},{"15",UC_MIPS_REG_15},{"16",UC_MIPS_REG_16},{"17",UC_MIPS_REG_17},{"18",UC_MIPS_REG_18},{"19",UC_MIPS_REG_19},{"20",UC_MIPS_REG_20},{"21",UC_MIPS_REG_21},{"22",UC_MIPS_REG_22},{"23",UC_MIPS_REG_23},{"24",UC_MIPS_REG_24},{"25",UC_MIPS_REG_25},{"26",UC_MIPS_REG_26},{"27",UC_MIPS_REG_27},{"28",UC_MIPS_REG_28},{"29",UC_MIPS_REG_29},{"30",UC_MIPS_REG_30},{"31",UC_MIPS_REG_31},{"DSPCCOND",UC_MIPS_REG_DSPCCOND},{"DSPCARRY",UC_MIPS_REG_DSPCARRY},{"DSPEFI",UC_MIPS_REG_DSPEFI},{"DSPOUTFLAG",UC_MIPS_REG_DSPOUTFLAG},{"DSPOUTFLAG16_19",UC_MIPS_REG_DSPOUTFLAG16_19},{"DSPOUTFLAG20",UC_MIPS_REG_DSPOUTFLAG20},{"DSPOUTFLAG21",UC_MIPS_REG_DSPOUTFLAG21},{"DSPOUTFLAG22",UC_MIPS_REG_DSPOUTFLAG22},{"DSPOUTFLAG23",UC_MIPS_REG_DSPOUTFLAG23},{"DSPPOS",UC_MIPS_REG_DSPPOS},{"DSPSCOUNT",UC_MIPS_REG_DSPSCOUNT},{"AC0",UC_MIPS_REG_AC0},{"AC1",UC_MIPS_REG_AC1},{"AC2",UC_MIPS_REG_AC2},{"AC3",UC_MIPS_REG_AC3},{"CC0",UC_MIPS_REG_CC0},{"CC1",UC_MIPS_REG_CC1},{"CC2",UC_MIPS_REG_CC2},{"CC3",UC_MIPS_REG_CC3},{"CC4",UC_MIPS_REG_CC4},{"CC5",UC_MIPS_REG_CC5},{"CC6",UC_MIPS_REG_CC6},{"CC7",UC_MIPS_REG_CC7},{"F0",UC_MIPS_REG_F0},{"F1",UC_MIPS_REG_F1},{"F2",UC_MIPS_REG_F2},{"F3",UC_MIPS_REG_F3},{"F4",UC_MIPS_REG_F4},{"F5",UC_MIPS_REG_F5},{"F6",UC_MIPS_REG_F6},{"F7",UC_MIPS_REG_F7},{"F8",UC_MIPS_REG_F8},{"F9",UC_MIPS_REG_F9},{"F10",UC_MIPS_REG_F10},{"F11",UC_MIPS_REG_F11},{"F12",UC_MIPS_REG_F12},{"F13",UC_MIPS_REG_F13},{"F14",UC_MIPS_REG_F14},{"F15",UC_MIPS_REG_F15},{"F16",UC_MIPS_REG_F16},{"F17",UC_MIPS_REG_F17},{"F18",UC_MIPS_REG_F18},{"F19",UC_MIPS_REG_F19},{"F20",UC_MIPS_REG_F20},{"F21",UC_MIPS_REG_F21},{"F22",UC_MIPS_REG_F22},{"F23",UC_MIPS_REG_F23},{"F24",UC_MIPS_REG_F24},{"F25",UC_MIPS_REG_F25},{"F26",UC_MIPS_REG_F26},{"F27",UC_MIPS_REG_F27},{"F28",UC_MIPS_REG_F28},{"F29",UC_MIPS_REG_F29},{"F30",UC_MIPS_REG_F30},{"F31",UC_MIPS_REG_F31},{"FCC0",UC_MIPS_REG_FCC0},{"FCC1",UC_MIPS_REG_FCC1},{"FCC2",UC_MIPS_REG_FCC2},{"FCC3",UC_MIPS_REG_FCC3},{"FCC4",UC_MIPS_REG_FCC4},{"FCC5",UC_MIPS_REG_FCC5},{"FCC6",UC_MIPS_REG_FCC6},{"FCC7",UC_MIPS_REG_FCC7},{"W0",UC_MIPS_REG_W0},{"W1",UC_MIPS_REG_W1},{"W2",UC_MIPS_REG_W2},{"W3",UC_MIPS_REG_W3},{"W4",UC_MIPS_REG_W4},{"W5",UC_MIPS_REG_W5},{"W6",UC_MIPS_REG_W6},{"W7",UC_MIPS_REG_W7},{"W8",UC_MIPS_REG_W8},{"W9",UC_MIPS_REG_W9},{"W10",UC_MIPS_REG_W10},{"W11",UC_MIPS_REG_W11},{"W12",UC_MIPS_REG_W12},{"W13",UC_MIPS_REG_W13},{"W14",UC_MIPS_REG_W14},{"W15",UC_MIPS_REG_W15},{"W16",UC_MIPS_REG_W16},{"W17",UC_MIPS_REG_W17},{"W18",UC_MIPS_REG_W18},{"W19",UC_MIPS_REG_W19},{"W20",UC_MIPS_REG_W20},{"W21",UC_MIPS_REG_W21},{"W22",UC_MIPS_REG_W22},{"W23",UC_MIPS_REG_W23},{"W24",UC_MIPS_REG_W24},{"W25",UC_MIPS_REG_W25},{"W26",UC_MIPS_REG_W26},{"W27",UC_MIPS_REG_W27},{"W28",UC_MIPS_REG_W28},{"W29",UC_MIPS_REG_W29},{"W30",UC_MIPS_REG_W30},{"W31",UC_MIPS_REG_W31}
    };
    const int numEntries=sizeof(register_array) / sizeof(register_array[0]);
    return index < numEntries ? register_array[index].name : "Invalid";
}
/************************************************** uc_reg_from_int_mips and register_name_from_int_mips MUST MATCH ************************************/



/**********************************************
 **** getting the integers from the name   ****
 **********************************************/
uint64_t register_int_from_name_mips(const char* reg_name)
{
    for (int i=0;i<MAX_REGISTERS;i++)
    {
        if (strcasecmp(reg_name,register_name_from_int_mips(i)) == 0)
        {
            return i;
        }
    }
    fprintf(stderr, "Error %s is not a valid register for mips.\n",reg_name);
    fprintf(stderr, "Valid choices are:");
    for (int i=0;i<MAX_REGISTERS;i++)
    {
        fprintf(stderr, "%s ",register_name_from_int_mips(i));
    }
    fprintf(stderr, "\n");
    my_exit(-1);
    return 666;  /// just here to keep the compiler happy. 
}