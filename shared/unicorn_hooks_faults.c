#include <capstone/capstone.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include "unicorn_engine.h"
#include "unicorn_consts.h"
#include "configuration.h"
#include "state.h"
#include "structs.h"
#include "utils.h"
#include "fileio.h"

extern bool is_equivalent (uc_engine* uc,current_run_state_t* current_run_state);

void delete_hook_code_fault_it_address(uc_engine *uc, current_run_state_t *current_run_state)
{
    // DELETE the fault hook
    if (current_run_state->hk_fault_address != 0)
    {
        my_uc_hook_del("hk_fault_address",uc, current_run_state->hk_fault_address, current_run_state);
        current_run_state->hk_fault_address=0;
    }
}

void delete_hook_code_fault_it(uc_engine *uc, current_run_state_t *current_run_state)
{
    // DELETE the fault hook
    if (current_run_state->hk_fault_it != 0)
    {
        my_uc_hook_del("hk_fault_it",uc, current_run_state->hk_fault_it, current_run_state);
        current_run_state->hk_fault_it=0;
    }
}

void add_hook_code_fault_it_address(uc_engine *uc, current_run_state_t* current_run_state, uint64_t address_to_fault)
{
    address_to_fault=thumb_check_address(address_to_fault);
#ifdef DEBUG
    printf_debug("add_hook_code_fault_it_address. Address to fault 0x%" PRIx64 ". Count: %li\n", 
        address_to_fault, current_run_state->instruction_count);
#endif
    if (current_run_state->fault_rule.target == reg_ft)
    {
        my_uc_hook_add("hk_fault_address", uc, &current_run_state->hk_fault_address, UC_HOOK_CODE, hook_code_fault_it_address, current_run_state, address_to_fault, address_to_fault);
    }
    else   if  (current_run_state->fault_rule.target == instruction_ft)
    {
        my_uc_hook_add("hk_fault_it instruction", uc, &current_run_state->hk_fault_it, UC_HOOK_CODE, hook_code_fault_it_instruction, current_run_state, address_to_fault, address_to_fault);
    }
    else   if  (current_run_state->fault_rule.target == instruction_pointer_ft)
    {
        my_uc_hook_add("hk_fault_it IP", uc, &current_run_state->hk_fault_it, UC_HOOK_CODE, hook_code_fault_it_IP, current_run_state, address_to_fault, address_to_fault);
    }
    else
    {
        fprintf(stderr, "Target not found: %s\n", target_to_string(current_run_state->fault_rule.target));
        my_exit(-1);  
    }
}

void hook_code_equivalent(uc_engine *uc, uint64_t address, uint64_t size, void *user_data)
{
    current_run_state_t *current_run_state=(current_run_state_t *)user_data;
    if (is_equivalent(uc, current_run_state))
    {
            // If we've found an equivalence - stop the run - no point in doing something if we've done it before!
            current_run_state->run_state=EQUIVALENT_rs;
            my_uc_emu_stop(uc);
            return;
    }
    my_uc_hook_del("hk_equivalent",uc, current_run_state->hk_equivalent,current_run_state);
    current_run_state->hk_equivalent=0;
}

void hook_code_fault_it_address(uc_engine *uc, uint64_t address, uint64_t size, void *user_data)
{
    current_run_state_t *current_run_state=(current_run_state_t *)user_data;
    #ifdef DEBUG
            printf_debug("hook_code_fault_it_address - called Address 0x%" PRIx64 ". Count: %li\n", address, current_run_state->instruction_count);
    #endif

    if (current_run_state->in_fault_range == 0)
    {
        return;
    }
    if (current_run_state->run_state == FAULTED_rs)
    {
        // Don't fault it more than once.
        return;
    }
    if (current_run_state->fault_rule.instruction != current_run_state->instruction_count)
    {
        // only fault the specific instruction
        return;
    }

    #ifdef DEBUG
            printf_debug("hook_code_fault_it_address - faulting. Address 0x%" PRIx64 ". Count: %li\n", address, current_run_state->instruction_count);
    #endif

    // set the address where this fault occurred
    current_run_state->fault_rule.faulted_address=address;

    // This next hook will do the actual fault. The reasoning for this: 
    // This hook is reached BEFORE the instruction has been executed. So if we want to bit flip the result of the execution we have to do it in the next instruction.
    my_uc_hook_add("hk_fault_it register", uc, &current_run_state->hk_fault_it, UC_HOOK_CODE, hook_code_fault_it_register, current_run_state, 1, 0);
    // delete this hook
    delete_hook_code_fault_it_address(uc, current_run_state);
}

void hook_code_start_faults(uc_engine *uc, uint64_t address, uint64_t size, void *user_data)
{
    current_run_state_t *current_run_state=(current_run_state_t *)user_data;

    #ifdef DEBUG
        printf_debug("hook_code_start_faults. Address: 0x%" PRIx64 "\n", address);
    #endif
    // We've hit the first address for faulting.
    if (current_run_state->run_mode == eGOLDEN_rm)
    {
        // Only show the IN/OUT fault range if we're running the program to see all the instructions
        fprintf(current_run_state->file_fprintf,"  <~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>  IN fault range!!! 0x%" PRIx64 "  <~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>\n",address); 
    }
    current_run_state->in_fault_range=1;
    if (current_run_state->instruction_count == 0)
    {
        // This is the first time we're in the faulting range
        current_run_state->instruction_count=1;  // We're off
    }
    // Add the hook that will start counting instructions. q
    if (current_run_state->hk_count_instructions == 0)
    { 
        my_uc_hook_add("hk_count_instructions", uc, &current_run_state->hk_count_instructions, UC_HOOK_CODE, hook_count_instructions, current_run_state, 1, 0);
    }
}

void hook_code_stop_faults(uc_engine *uc, uint64_t address, uint64_t size, void *user_data)
{
    current_run_state_t *current_run_state=(current_run_state_t *)user_data;
#ifdef DEBUG
    printf("<~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~> OUT fault range!!! 0x%" PRIx64 ". uc: %p. Count: %li\n",address,uc,current_run_state->instruction_count); 
    printf_debug("hook_code_stop_faults. Address 0x%" PRIx64 "\n", address);
#endif

    if (current_run_state->run_mode == eGOLDEN_rm)
    {
        // Only show the IN/OUT fault range if we're running the program to see all the instructions
        fprintf(current_run_state->file_fprintf,"  <~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~> OUT fault range!!! 0x%" PRIx64 ". Count: %llu\n",address,current_run_state->instruction_count); 
    }
    current_run_state->in_fault_range=0;
}

void hook_code_hard_stop(uc_engine *uc, uint64_t address, uint64_t size, void *user_data)
{
#ifdef DEBUG
    printf_debug("hook_code_hard_stop. Address 0x%" PRIx64 "\n", address);
#endif

    current_run_state_t *current_run_state = (current_run_state_t *)user_data;

    current_run_state->run_state=HARD_STOP_rs;
    fprintf(current_run_state->file_fprintf, "~~~~ Reached a hard stop address 0x%" PRIx64 " ~~~~\n", address);

    delete_hook_count_instructions(uc, current_run_state);
    my_uc_emu_stop(uc);
}

void hook_intr(uc_engine *uc, uint64_t int_no, void *user_data)
{
#ifdef DEBUG
    printf_debug("hook_intr\n");
#endif
    current_run_state_t *current_run_state=(current_run_state_t *)user_data;
    fprintf(current_run_state->file_fprintf, "Hook intr. Interrupt number: %lli \n", int_no);
    current_run_state->run_state=INTERRUPT_rs;
    my_uc_emu_stop(uc);
}

void hook_memory_invalid(uc_engine *uc, uc_mem_type type, uint64_t address, uint64_t size, uint64_t value, void *user_data)
{
#ifdef DEBUG
    printf_debug("hook_memory_invalid. Address 0x%" PRIx64 "\n", address);
#endif
    current_run_state_t *current_run_state=(current_run_state_t *)user_data;
    if (type == UC_MEM_READ_UNMAPPED)
    {
        fprintf(current_run_state->file_fprintf, " >! Errored: ʕ•ᴥ•ʔ  Oopsie    - reading from unmapped memory, address: 0x%016llx, value: 0x%" PRIx64 "!!\n", address, value);
    }
    else if (type == UC_MEM_WRITE_UNMAPPED)
    {
        fprintf(current_run_state->file_fprintf, " >! Errored: /ᐠ.ꞈ.ᐟ\\  Hmm - writing to unmapped memory, address: 0x%" PRIx64 ", value: 0x%" PRIx64 "!! Count %lli Skipping to end.\n", address, value,current_run_state->instruction_count);
    }
    else if (type == UC_MEM_FETCH_PROT)
    {
        fprintf(current_run_state->file_fprintf, " >! Errored: ¯\\_(ツ)_/¯ Doh - invalid memory fetch from address: 0x%" PRIx64 ", value: 0x%" PRIx64 ". Count %" PRIx64 "!!\n", address, value,current_run_state->instruction_count);
    }
    else if (type == UC_MEM_FETCH_UNMAPPED)
    {
        fprintf(current_run_state->file_fprintf, " >! Errored: Erm -  fetching from unmapped memory, address: 0x%" PRIx64 ", value: 0x%" PRIx64 ". Count %" PRIx64 "!! Skipping to end.\n", address, value,current_run_state->instruction_count);
    }
    else if (type == UC_MEM_WRITE_PROT)
    {
        fprintf(current_run_state->file_fprintf, " >! Errored: WOT - write to non-writeable memory from address: 0x%" PRIx64 ", value: 0x%" PRIx64 "!!\n", address, value);
    }
    else if (type == UC_MEM_READ_PROT)
    {
        fprintf(current_run_state->file_fprintf, " >! Errored: Huh - read from non-readable memory from address: 0x%" PRIx64 ", value: 0x%" PRIx64 "!!\n", address, value);
    }
    else
    {
        fprintf(current_run_state->file_fprintf, " >! Errored: Something something something - strange invalid memory error. Address: 0x%" PRIx64 ", value: 0x%" PRIx64 "!!\n", address, value);
    }

    current_run_state->run_state=ERRORED_rs;
    my_uc_emu_stop(uc);
}



void hook_instruction_invalid (uc_engine *uc,void *user_data)
{
#ifdef DEBUG
    printf_debug("hook_instruction_invalid. \n");
#endif
    current_run_state_t *current_run_state=(current_run_state_t *)user_data;
    fprintf_output(current_run_state->file_fprintf, "Instruction invalid.\n");
    current_run_state->run_state=ERRORED_rs;
    my_uc_emu_stop(uc);
}
