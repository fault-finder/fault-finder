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

#define FAULT_AFTER false  // Do you do the fault BEFORE or after the isntruction has completed?
extern bool is_equivalent (uc_engine* uc,current_run_state_t* current_run_state);

void do_the_register_fault(uc_engine* uc, current_run_state_t* current_run_state,uint64_t address,uint64_t size)
{
    // Do the faulting now
    uint64_t original_val=0, new_val=0, thing_to_fault=0;
    fault_rule_t* this_fault=&current_run_state->fault_rule;

    //read it
    thing_to_fault=uc_reg_from_int(this_fault->number);
    uc_reg_read(uc, thing_to_fault, &original_val);
    fprintf_output(current_run_state->file_fprintf, "Original register           : 0x%016llx \n", original_val);
    fprintf_output(current_run_state->file_fprintf, "Mask                        : 0x%016" PRIx64 "\n", this_fault->mask);

    //fault it
    new_val=fault_reg(this_fault->mask, this_fault->operation, original_val, size);
        
    this_fault->lifespan.original_target_value=original_val;
    // write it back (reg/instruction pointer all work the same)
    uc_reg_write(uc, thing_to_fault, &new_val);
    fprintf_output(current_run_state->file_fprintf, "Updated                     : 0x%016llx\n", new_val);
}

void hook_code_fault_it_register(uc_engine *uc, uint64_t address, uint64_t size, void *user_data)
{
    /*** This is where the faulting actually happens ****/
    current_run_state_t *current_run_state=(current_run_state_t *)user_data;
    fault_rule_t *this_fault=&current_run_state->fault_rule;
    uint64_t fault_address = current_run_state->line_details_array[this_fault->instruction].address;
    fault_address=thumb_check_address(fault_address);

    #ifdef DEBUG
            printf_debug("hook_code_fault_it_register. Address 0x%" PRIx64 ". Count: %li\n", address, current_run_state->instruction_count);
    #endif

    // If we want to fault AFTER the instruction then we need to skip this once.
    if (fault_address == address && FAULT_AFTER)
    {
        return;
    }
    #ifdef DEBUG
            printf_debug("Faulting this line. Address 0x%" PRIx64 ". Count: %li\n", address, current_run_state->instruction_count);
    #endif
    do_the_register_fault(uc, current_run_state,address,size);
    
    // if we are using revert lifespan then we'll need the original value!
    if (this_fault->lifespan.count != 0)
    {
        this_fault->lifespan.live_counter=this_fault->lifespan.count;
        if (this_fault->lifespan.mode == eREVERT_lsm)
        {
            my_uc_hook_add("hk_fault_lifespan revert", uc, &current_run_state->hk_fault_lifespan, UC_HOOK_CODE, hook_lifespan_revert_register, current_run_state, 1, 0);
        }
        if (this_fault->lifespan.mode == eREPEAT_lsm)
        {
            my_uc_hook_add("hk_fault_lifespan repeat", uc, &current_run_state->hk_fault_lifespan, UC_HOOK_CODE, hook_lifespan_repeat_register, current_run_state, 1, 0);
        }
    }

    // we've done the fault - so set run state to faulted!!
    current_run_state->run_state=FAULTED_rs;

    // Check for equivalences
    if (current_run_state->stop_on_equivalence && (is_equivalent(uc, current_run_state)))
    {
            // If we've found an equivalence - stop the run - no point in doing something if we've done it before!
            current_run_state->run_state=EQUIVALENT_rs;
            my_uc_emu_stop(uc);
            return;
    }
    delete_hook_code_fault_it(uc, current_run_state);
}

void hook_lifespan_revert_register(uc_engine *uc, uint64_t address, uint64_t size, void *user_data)
{
    current_run_state_t *current_run_state=(current_run_state_t *)user_data;
    fault_rule_t* this_fault=&current_run_state->fault_rule;
    uint64_t fault_at_instruction=this_fault->instruction;
    uint64_t fault_address=current_run_state->line_details_array[fault_at_instruction].address;
    fault_address=thumb_check_address(fault_address);

    if (address == fault_address && this_fault->lifespan.count == this_fault->lifespan.live_counter)
    {
        // The lifespan starts AFTER the faulted address.
        return;
    }
    fprintf_output(current_run_state->file_fprintf,"Lifespan revert countdown: %llu. (0x%" PRIx64 ")\n",this_fault->lifespan.count,address);
    this_fault->lifespan.live_counter--; 
    if (this_fault->lifespan.live_counter != 0)
        return;

    // REVERT THE FAULT
    uint64_t value_to_revert=this_fault->lifespan.original_target_value;
    uint64_t thing_to_fault=0;

    switch (this_fault->target)
    {
        case reg_ft:
            //read it
            thing_to_fault=this_fault->number;
            fprintf_output(current_run_state->file_fprintf, "Reverting register (%s)        : 0x%016llx \n", register_name_from_int(thing_to_fault), value_to_revert);
                //revert it
            uc_reg_write(uc, uc_reg_from_int(thing_to_fault), &value_to_revert); 
            break;
        case instruction_pointer_ft:
            //read it
            thing_to_fault=binary_file_details->my_pc_reg;
            fprintf_output(current_run_state->file_fprintf, "Reverting instruction pointer: 0x%016llx\n", value_to_revert);
                //revert it
            uc_reg_write(uc, thing_to_fault, &value_to_revert); 
            break;
        default:
            fprintf(stderr, "Failed to find valid target to revert: %s\n", target_to_string(this_fault->target));
            my_exit(-1);
    }
        my_uc_hook_del("hk_fault_lifespan",uc, current_run_state->hk_fault_lifespan,current_run_state);
        current_run_state->hk_fault_lifespan=0;
}

void hook_lifespan_repeat_register(uc_engine *uc, uint64_t address, uint64_t size, void *user_data)
{
    current_run_state_t *current_run_state=(current_run_state_t *)user_data;
    fault_rule_t* this_fault=&current_run_state->fault_rule;
    uint64_t fault_at_instruction=this_fault->instruction;
    uint64_t fault_address=current_run_state->line_details_array[fault_at_instruction].address;
    fault_address=thumb_check_address(fault_address);

    if (address == fault_address && this_fault->lifespan.count == this_fault->lifespan.live_counter)
    {
        // The repeated faults start AFTER the faulted address.
        return;
    }
    fprintf_output(current_run_state->file_fprintf,"Lifespan register repeat countdown: %llu. (0x%" PRIx64 ")\n",this_fault->lifespan.count,address);
    
    this_fault->lifespan.live_counter--; 

    do_the_register_fault(uc, current_run_state,address,size);

    if (this_fault->lifespan.live_counter == 0)
    {
        // delete this hook
        my_uc_hook_del("hk_fault_lifespan",uc, current_run_state->hk_fault_lifespan,current_run_state);
        current_run_state->hk_fault_lifespan=0;
    }
}
