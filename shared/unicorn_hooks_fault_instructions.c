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


void do_the_instruction_fault(uc_engine* uc, current_run_state_t* current_run_state,uint64_t address,uint64_t size)
{
    /*** This is where the faulting actually happens for INSTRUCTIONS ****/
    uint8_t* instruction_original=MY_STACK_ALLOC(sizeof(uint8_t)*(size+1));
    uint8_t* instruction_new=MY_STACK_ALLOC(sizeof(uint8_t)*(size+1));

    if (size > 8)
    {
        fprintf_output(current_run_state->file_fprintf," Warning. The instruction for this line is longer than 8 bytes - the mask may not be large enough.\n"); 
    }

    //read it
    uc_mem_read(uc,address,instruction_original,size);
    uint64_t fault_address=thumb_check_address(address);
    fprintf_output(current_run_state->file_fprintf, "Fault Address                  :  0x%" PRIx64 "\n",address);
    fprintf_output(current_run_state->file_fprintf, "Original instruction           :  ");
    for (int i=0;i<size;i++)
    {
        fprintf(current_run_state->file_fprintf,"%02x ",instruction_original[i]);
    }

    fault_rule_t *this_fault=&current_run_state->fault_rule;
    if (current_run_state->display_disassembly && binary_file_details->my_cs_arch != MY_CS_ARCH_NONE)
    {
        // Can be turned off to save time - although I've not done the time calculations to see if it saves much time
        disassemble_instruction_and_print(current_run_state->file_fprintf,instruction_original,size); 
    }
    else
    {
        fprintf(current_run_state->file_fprintf,"\n");
    }
    fprintf_output(current_run_state->file_fprintf, "Mask                           :  0x%" PRIx64 "\n", this_fault->mask);

    //fault it
    fault_instruction(this_fault->mask, this_fault->operation, instruction_original,instruction_new, size,current_run_state->file_fprintf);
    uc_mem_write(uc,fault_address,instruction_new,size);
    fprintf_output(current_run_state->file_fprintf, "Updated instruction            :  ");
    for (int i=0;i<size;i++)
    {
        fprintf(current_run_state->file_fprintf,"%02x ",instruction_new[i]);
    }
    if (current_run_state->display_disassembly && binary_file_details->my_cs_arch != MY_CS_ARCH_NONE )
    {
        // Can be turned off to save time - although I've not done the time calculations to see if it saves much time
        disassemble_instruction_and_print(current_run_state->file_fprintf,instruction_new,size); 
    }
    fprintf(current_run_state->file_fprintf,"\n");
    // if we are using lifespan then we'll need the original instruction!
    this_fault->lifespan.original_instruction_value_size=size;
    memcpy(this_fault->lifespan.original_instruction_value,instruction_original,size);

    // set the address where this fault occurred
    this_fault->faulted_address=address;

    // we've done the fault - so set faulting_mode to faulted!!
    current_run_state->run_state=FAULTED_rs;
}

void my_uc_ctl_remove_cache(uc_engine *uc, uint64_t address_start,uint64_t address_end)
{   
    address_start-= 0x1;
    address_end+= 0x1;
    uc_ctl_remove_cache(uc, address_start, address_end);
}

void hook_code_fault_it_instruction(uc_engine *uc, uint64_t address, uint64_t size, void *user_data)
{
    current_run_state_t *current_run_state=(current_run_state_t *)user_data;

#ifdef DEBUG
        printf_debug("hook_code_fault_it_instruction. Address 0x%" PRIx64 ". Count: %li\n", address, current_run_state->instruction_count);
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
    //For instructions we have to trigger it one before.
    if (current_run_state->fault_rule.instruction != current_run_state->instruction_count)
    {
        // only fault the specific instruction
        return;
    }
    do_the_instruction_fault(uc, current_run_state,address,size);
    

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
            my_uc_hook_add("hk_fault_lifespan revert", uc, &current_run_state->hk_fault_lifespan, UC_HOOK_CODE, hook_lifespan_revert_instruction, current_run_state, 1, 0);
        }
        if (this_fault->lifespan.mode == eREPEAT_lsm)
        {
            my_uc_hook_add("hk_fault_lifespan repeat", uc, &current_run_state->hk_fault_lifespan, UC_HOOK_CODE, hook_lifespan_repeat_instruction, current_run_state, address, address);
        }
    }

    uint64_t new_address=address;
    if ((binary_file_details->my_uc_arch == UC_ARCH_ARM || binary_file_details->my_uc_arch == UC_ARCH_ARM64) )
        new_address++;     /* Add 1 for thumb */

    my_uc_ctl_remove_cache(uc, address, address);

    current_run_state->restart=true;
    current_run_state->restart_address=new_address; //includes the +1 if it's thumb

    // We have to stop and start the emulation for an instruction change.
    uc_emu_stop(uc);
    delete_hook_code_fault_it(uc, current_run_state); 
}

void hook_lifespan_repeat_instruction(uc_engine *uc, uint64_t address, uint64_t size, void *user_data)
{
    current_run_state_t *current_run_state=(current_run_state_t *)user_data;
    fault_rule_t* this_fault=&current_run_state->fault_rule;
    uint64_t fault_at_instruction=this_fault->instruction;
    uint64_t current_instruction_count=current_run_state->instruction_count;

    if (current_instruction_count <=(fault_at_instruction+1))
    {
        // The lifespan starts AFTER the faulted address.
        return;
    }
    // we're repeating the fault 
    fprintf_output(current_run_state->file_fprintf,"Lifespan repeat (instruction): %llu. (0x%" PRIx64 ") \n",this_fault->lifespan.live_counter,address);

    // FAULT IT AGAIN HERE---------------------------------
    do_the_instruction_fault(uc, current_run_state,address,size);
    // FAULT IT AGAIN HERE---------------------------------

    this_fault->lifespan.live_counter--; 
    // We've hit zero - so no more repeating the fault.
    if (this_fault->lifespan.live_counter == 0)
    {
        // delete this hook
        my_uc_hook_del("hk_fault_lifespan",uc, current_run_state->hk_fault_lifespan,current_run_state);
        current_run_state->hk_fault_lifespan=0;
    }

    /* Fixing for thumb */
    uint64_t new_address=address;
    if ((binary_file_details->my_uc_arch == UC_ARCH_ARM || binary_file_details->my_uc_arch == UC_ARCH_ARM64) && size == 2)
        new_address++;

    my_uc_ctl_remove_cache(uc, address, address);
    current_run_state->restart=true;
    current_run_state->restart_address=new_address; //includes the +1 if it's thumb

    // the count needs to go back one - because it will continue counting.
    current_run_state->instruction_count--;

    // We have to stop and start the emulation for an instruction change.
    uc_emu_stop(uc);
}

void hook_lifespan_revert_instruction(uc_engine *uc, uint64_t address, uint64_t size, void *user_data)
{
    current_run_state_t *current_run_state=(current_run_state_t *)user_data;
    fault_rule_t* this_fault=&current_run_state->fault_rule;
    uint64_t fault_at_instruction=this_fault->instruction;
    uint64_t current_instruction_count=current_run_state->instruction_count;
    uint64_t fault_address=current_run_state->line_details_array[fault_at_instruction].address;

    if (current_instruction_count <=(fault_at_instruction+1))
    {
        // The lifespan starts AFTER the faulted address.
        return;
    }
    fprintf_output(current_run_state->file_fprintf,"Lifespan revert countdown (instruction): %llu. (0x%" PRIx64 ") \n",this_fault->lifespan.live_counter,address);
    this_fault->lifespan.live_counter--; 
    if (this_fault->lifespan.live_counter != 0)
        return;

    fault_address=thumb_check_address(fault_address);

    // we're reverting the instruction 
    fprintf_output(current_run_state->file_fprintf, "Reverting address              :  0x%" PRIx64 "\n",fault_address);
    fprintf_output(current_run_state->file_fprintf, "Reverting instruction          :  ");
    for (uint64_t i=0;i<this_fault->lifespan.original_instruction_value_size ;i++)
    {
        fprintf(current_run_state->file_fprintf,"%02x ",this_fault->lifespan.original_instruction_value[i]);
    }
    fprintf (current_run_state->file_fprintf,"\n");
    my_uc_ctl_remove_cache(uc, fault_address, fault_address);
    uc_mem_write(uc,fault_address,this_fault->lifespan.original_instruction_value,this_fault->lifespan.original_instruction_value_size);
    my_uc_ctl_remove_cache(uc, fault_address, fault_address);

    // delete this hook
    my_uc_hook_del("hk_fault_lifespan",uc, current_run_state->hk_fault_lifespan,current_run_state);
    current_run_state->hk_fault_lifespan=0;

    /* Fixing for thumb */
    uint64_t new_address=address;
    if ((binary_file_details->my_uc_arch == UC_ARCH_ARM || binary_file_details->my_uc_arch == UC_ARCH_ARM64))
        new_address++;

    current_run_state->restart=true;
    current_run_state->restart_address=new_address; //includes the +1 if it's thumb

    // the count needs to go back one - because it will continue counting.
    current_run_state->instruction_count--;

    // We have to stop and start the emulation for an instruction change.
    uc_emu_stop(uc);
    delete_hook_code_fault_it(uc, current_run_state); 
}
