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

void do_the_IP_fault(uc_engine* uc, current_run_state_t* current_run_state,uint64_t address,uint64_t size)
{
    uint64_t pc_value=0;
    uc_reg_read(uc,binary_file_details->my_pc_reg,&pc_value);       // read it

    fprintf_output(current_run_state->file_fprintf, "Fault Address                  :  0x%" PRIx64 "\n",address);
    fprintf_output(current_run_state->file_fprintf, "Original IP                    :  0x%" PRIx64 "\n",pc_value);

    //fault it
    pc_value=IP_fault_skip(current_run_state->fault_rule.operation, pc_value, size);

    uc_reg_write(uc,binary_file_details->my_pc_reg,&pc_value);      // write it
    fprintf_output(current_run_state->file_fprintf, "Updated IP                     :  0x%" PRIx64 "\n",pc_value);

    // set the address where this fault occurred
    current_run_state->fault_rule.faulted_address=address;

    // we've done the fault - so set faulting_mode to faulted!!
    current_run_state->run_state=FAULTED_rs;
    
    // we have to increase the count because we're skipping an instruction.
    current_run_state->instruction_count++;
}


void hook_lifespan_repeat_IP(uc_engine *uc, uint64_t address, uint64_t size, void *user_data)
{
    current_run_state_t *current_run_state=(current_run_state_t *)user_data;
    fault_rule_t* this_fault=&current_run_state->fault_rule;
    uint64_t fault_at_instruction=this_fault->instruction;
    uint64_t fault_address=current_run_state->line_details_array[fault_at_instruction].address;
    fault_address=thumb_check_address(fault_address);

    if (this_fault->instruction == current_run_state->instruction_count )
    {
        return;         // The repeated faults start AFTER the faulted address.
    }
    fprintf_output(current_run_state->file_fprintf,"Lifespan skip repeat countdown: %llu. (0x%" PRIx64 ") %" PRId64 "\n",this_fault->lifespan.count,address,current_run_state->instruction_count);
    
    this_fault->lifespan.live_counter--; 

    do_the_IP_fault(uc, current_run_state,address,size);

    if (this_fault->lifespan.live_counter == 0)
    {
        // delete this current hook
        my_uc_hook_del("hk_fault_lifespan",uc, current_run_state->hk_fault_lifespan,current_run_state);
        current_run_state->hk_fault_lifespan=0;
    }
}

void hook_code_fault_it_IP(uc_engine *uc, uint64_t address, uint64_t size, void *user_data)
{
    current_run_state_t *current_run_state=(current_run_state_t *)user_data;

#ifdef DEBUG
        printf_debug("hook_code_fault_it_IP. Address 0x%" PRIx64 ". Count: %li\n", address, current_run_state->instruction_count);
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
    do_the_IP_fault(uc, current_run_state,address,size);

    // Check for equivalences
    if (current_run_state->stop_on_equivalence)
    {
        my_uc_hook_add("hk_equivalent", uc, &current_run_state->hk_equivalent, UC_HOOK_CODE, hook_code_equivalent, current_run_state, 1, 0);
    }

    fault_rule_t *this_fault=&current_run_state->fault_rule;
    if (this_fault->lifespan.count != 0)
    {
        this_fault->lifespan.live_counter=this_fault->lifespan.count;
        if (this_fault->lifespan.mode == eREVERT_lsm)
        {
            fprintf_output(current_run_state->file_fprintf, "Note: You can't revert a skip instruction. Ignored.\n");
        }
        if (this_fault->lifespan.mode == eREPEAT_lsm)
        {
            fprintf_output(current_run_state->file_fprintf, "Note: repeating this fault %llu times.\n",this_fault->lifespan.count);
            my_uc_hook_add("hk_fault_lifespan(IP)", uc, &current_run_state->hk_fault_lifespan, UC_HOOK_CODE, hook_lifespan_repeat_IP, current_run_state, address, address);
        }
    }

    // We don't have to restart with IP  - the code isn't changing - just the instruction pointer.
    delete_hook_code_fault_it(uc, current_run_state); 
}
