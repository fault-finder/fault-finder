#include <capstone/capstone.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "unicorn_engine.h"
#include "unicorn_consts.h"
#include "structs.h"
#include "utils.h"
#include "fileio.h"
#include "configuration.h"


void hook_placebo (uc_engine *uc, uint64_t address, uint64_t size, void *user_data)
{
}

void hook_min_max_mod (uc_engine *uc, uint64_t address, uint64_t size, void *user_data)
{
    current_run_state_t *current_run_state=(current_run_state_t *)user_data;
    /* if (current_run_state->in_fault_range == 0)
    {
        return;
    }*/

    // Getting the smallest address
    if (current_run_state->address_hit_counter->min_address>address)
    {
        current_run_state->address_hit_counter->min_address=address;
    }

    // Getting the biggest address
    if (current_run_state->address_hit_counter->max_address<address)
    {
        current_run_state->address_hit_counter->max_address=address;
    }
    for (uint64_t i=2;i<current_run_state->address_hit_counter->mod_address;i++)
    {
        if ((address % i) == 0)
        {
            current_run_state->address_hit_counter->mod_address=i;
        }
    }

}
void delete_hook_count_instructions(uc_engine *uc, current_run_state_t *current_run_state)
{
    // DELETE the counting hook
    if (current_run_state->hk_count_instructions != 0)
    {
        my_uc_hook_del("hk_count_instructions",uc, current_run_state->hk_count_instructions, current_run_state);
        current_run_state->hk_count_instructions=0;
    }
}

void hook_code_start_address (uc_engine *uc, uint64_t address, uint64_t size, void *user_data)
{
    // We're at start address
    #ifdef DEBUG
        printf_debug("hook_code_start_address. Address: 0x%" PRIx64 ". Size: %li\n",address,size);
    #endif

    current_run_state_t *current_run_state=(current_run_state_t *)user_data;
    FILE* f=current_run_state->file_fprintf;
    uint64_t instr=current_run_state->fault_rule.instruction;
    if (current_run_state->run_state != NONE_rs)
    {
        fprintf(f, "We're at the start_address but the run result is not NONE but: %s. This could get messy.\n",
            run_state_to_string(current_run_state->run_state));
        fprintf(f, "Possibly the instruction pointer was faulted?\n");
        return;
    }

    // Add the hook that will do the actual fault
    if (current_run_state->fault_rule.set == true)
    {
        uint64_t address_to_fault=current_run_state->line_details_array[instr].address;

        // create the hook to do the actual fault.
        add_hook_code_fault_it_address(uc, current_run_state, address_to_fault);
    }

    if (current_run_state->run_mode == eTIMING_CHECKPOINT_rm)
    {
        struct timespec start, stop;
        if( clock_gettime( CLOCK_REALTIME, &start) == -1 ) 
        {
            fprintf(stderr,  "clock gettime" );
            my_exit( -1);
        }
        uc_restore_from_checkpoint(uc, current_run_state, current_run_state->total_instruction_count * 3 /4);

        if( clock_gettime( CLOCK_REALTIME, &stop) == -1 ) 
        {
            fprintf(stderr, "clock gettime" );
            my_exit( -1 );
        }
        current_run_state->time_to_restore_checkpoint=((stop.tv_sec - start.tv_sec )*BILLION) + ( stop.tv_nsec - start.tv_nsec );
    }
    // Restore from checkpoint
    if (    current_run_state->run_mode == eFAULT_rm && 
            current_run_state->start_from_checkpoint == true  &&
            current_run_state->fault_rule.set == true &&
            current_run_state->line_details_array[instr].nearest_checkpoint != NO_CHECKPOINT)
    {
        uc_restore_from_checkpoint(uc, current_run_state, current_run_state->fault_rule.instruction);
    }
}

void hook_code_end_address (uc_engine *uc, uint64_t address, uint64_t size, void *user_data)
{
    #ifdef DEBUG
        printf_debug("hook_code_end_address. Address: 0x%" PRIx64 ". Size: %li\n",address,size);
    #endif
    // Reached the end address. Which is a good thing!
    current_run_state_t *current_run_state=(current_run_state_t *)user_data;
    if (current_run_state->run_state == FAULTED_rs)
    {
        current_run_state->run_state=END_ADDRESS_AND_FAULTED_rs;
    }
    else if  (current_run_state->run_state == EQUIVALENT_rs)
    {
        /* Do nothing - we don't want to change the  */
        printf ("Got here  - but I thought I called uc_stop() - hmmmfmfmf\n");
    }
    else
    {
        current_run_state->run_state=END_ADDRESS_rs;
    }
     // Remove the hook that is counting faulted instructions
    delete_hook_count_instructions(uc, current_run_state);
    my_uc_emu_stop(uc);
}

void hook_count_instructions(uc_engine *uc, uint64_t address, uint64_t size, void *user_data)
{
    current_run_state_t *current_run_state=(current_run_state_t *)user_data;

    #ifdef DEBUG
        //printf_debug("hook_count_instructions. Address: %" PRIx64 ". Size: %li. Count: %li\n",address,size,current_run_state->instruction_count);
        printf("%" PRId64 ".",current_run_state->instruction_count);
    #endif
    current_run_state->last_address=address;

    if (current_run_state->in_fault_range == 0)
    {
        return;
    }
    // Simply counts the intructions in the faulting range
    current_run_state->instruction_count++; 
}

void hook_code_skips(uc_engine *uc, uint64_t address, uint64_t size, void *user_data)
{
    #ifdef DEBUG
        printf_debug("hook_code_skips. Address: 0x%" PRIx64 ". Size: %li\n",address,size);
    #endif
    current_run_state_t *current_run_state=(current_run_state_t *)user_data;
    // skips the instructions that the emulation can't cope with (user defined in .json file)
    for (int i=0;i<binary_file_details->skips_count;i++)
    {
        if ((binary_file_details->skips[i].address+binary_file_details->memory_main.address == address) && (binary_file_details->skips[i].bytes != 0))
        {
            size=binary_file_details->skips[i].bytes;
            #ifdef DEBUG
                printf_debug("hook_code_skips. Size overwritten: %li\n",size);
            #endif
            
        }
    }
    if (current_run_state->run_mode == eGOLDENRUN_FULL_rm || current_run_state->run_mode == eDEBUG_rm)
    {
        fprintf(current_run_state->file_fprintf,"Skipping address: 0x%" PRIx64 ". Size: %llu\n",address,size);
    }
    uint64_t tmp_reg=address + size;
    if (binary_file_details->my_uc_mode == UC_MODE_THUMB)
        tmp_reg++;
    uc_reg_write(uc, binary_file_details->my_pc_reg, &tmp_reg);
}

int disassemble_instruction_and_print(FILE* f,uint8_t* tmp,uint64_t size)
{
    int return_val=0;
    csh handle;
    cs_insn *insn=NULL;

    cs_err err=cs_open(binary_file_details->my_cs_arch, binary_file_details->my_cs_mode, &handle);
    if (err != CS_ERR_OK) 
    {
        fprintf(f, "Unable to open capstone to disassemble\n");
    }
    else
    {
            if (size<MAX_NUM_OF_BYTES_IN_OPCODE)   // This is defined at the top of this file
            {
                for (int j=0;j<MAX_NUM_OF_BYTES_IN_OPCODE-size;j++)
                    fprintf(f,"   "); //horrible hack to align the hex bytes
            }
            
            // Now disassemble this line using capstone and display the mnemonics
            size_t my_count=cs_disasm(handle, tmp, size, 0x1000, 0, &insn);
            if ( my_count > 0 )
            {
                fprintf(f,"\t: %s %s\n", insn[0].mnemonic, insn[0].op_str);
                return_val=1;
            } 
            else
            {
                fprintf_output(f, "\nUnable to disassemble opcode. Is it something very specific. Try skipping it?\n");
                return_val=0;
            }
            cs_free (insn,my_count);
    }

    cs_close(&handle); // Does this free insn?
    return return_val;
}
void hook_code_print_debug(uc_engine *uc, uint64_t address, uint64_t size, void *user_data)
{
    // current_run_state_t *current_run_state=(current_run_state_t *)user_data;

    // hook_code_print_instructions(uc, address, size, user_data);
    // print_outputs(uc,current_run_state);
    //     print_register_from_name(uc,stdout, "r8");
    //     print_register_from_name(uc,stdout, "rdi");
         print_register_from_name(uc,stdout, "r1");
         print_register_from_name(uc,stdout, "r3");
    //     print_register_from_name(uc,stdout, "r0");
    //     print_stack_from_sp(uc, stdout,0x40);
}


void hook_code_print_instructions(uc_engine *uc, uint64_t address, uint64_t size, void *user_data)
{
    current_run_state_t *current_run_state=(current_run_state_t *)user_data;

    #ifdef DEBUG
        printf_debug("hook_code_print_instructions. Address: %" PRIx64 ". Count: %li\n",address,current_run_state->instruction_count);
    #endif

    // Print the opcodes and address and counters
    uint8_t* tmp;
    tmp=MY_STACK_ALLOC(sizeof(uint8_t)*(size+1));

    // Read the line of code (opcode)
    if (!uc_mem_read(uc, address, tmp, size))
    {
        if (current_run_state->in_fault_range == 1)
        {
            fprintf(current_run_state->file_fprintf, "%08lli ",current_run_state->instruction_count);
            if (current_run_state->address_hit_counter != NULL && current_run_state->run_mode != eCOUNT_INSTRUCTIONS_rm)
            {
                if (current_run_state->line_details_array != NULL)
                {
                    // Do we ever get here?  yes maybe - if we compile with printinstruction
                    printf ("hit:%04lli. ", current_run_state->line_details_array[current_run_state->instruction_count].hit_count);
                }
                else
                {
                    printf ("hit:%04lli. ", address_hit(current_run_state->address_hit_counter,address));
                }
            }
        }
        else
        {
            // no counter or hit count if outside of faulting range.
            fprintf(current_run_state->file_fprintf, "~~~~~~~~ ");
        }



        fprintf(current_run_state->file_fprintf, "0x%08llx ",address);
        for (int i=0;i<size;i++)
        {
            fprintf(current_run_state->file_fprintf,"%02x ", tmp[i]);
        }


        if (current_run_state->display_disassembly && binary_file_details->my_cs_arch != MY_CS_ARCH_NONE)
        {
            // Can be turned off to save time - although I've not done the time calculations to see if it saves much time
            // uses capstone to disassemble and print the opcodes
            disassemble_instruction_and_print(current_run_state->file_fprintf,tmp,size);
        }
        else
        {
            fprintf(current_run_state->file_fprintf,"\n");
        }
    }
    else
    {
        fprintf(stderr,"Unable to read memory at 0x%" PRIx64 "\n",address);
        my_exit(-1);
    }
    /*DEBUGDEBUG*/
        // print_register_from_name(uc,stdout, "r0");
        // print_register_from_name(uc,stdout, "r1");
        // print_register_from_name(uc,stdout, "r2");
        // print_register_from_name(uc,stdout, "r3");
        // print_register_from_name(uc,stdout, "r4");
}

void hook_code_print_fault_instructions(uc_engine *uc, uint64_t address, uint64_t size, void *user_data)
{
    current_run_state_t *current_run_state=(current_run_state_t *)user_data;
    
    if (current_run_state->in_fault_range == 0)
    {
        return;
    }
    hook_code_print_instructions(uc, address,size, user_data);
}


void print_data_at_address(uc_engine *uc, uint64_t address, uint64_t size, void *user_data)
{
    #ifdef DEBUG
        printf_debug("print_data_at_address. Address: %" PRIx64 "\n",address);
    #endif
    current_run_state_t *current_run_state=(current_run_state_t *)user_data;
    uint8_t* tmp=alloca(sizeof(uint8_t)*size);
    uc_err err=uc_mem_read(uc, address, tmp, size);
    if (err == UC_ERR_OK)
    {
        fprintf(current_run_state->file_fprintf, "Printing data at address: 0x%" PRIx64 ". Value: ", address);
        for (int i=0;i<size;i++)
            fprintf(current_run_state->file_fprintf,"%x", tmp[i]);
        fprintf(current_run_state->file_fprintf, "\n");        
    }
    else
    {
        fprintf(current_run_state->file_fprintf, "Unable to read data at address: 0x%" PRIx64 "\n",address);  
    }
}

bool hook_mem_read_after(uc_engine *uc, uc_mem_type type, uint64_t address, uint64_t  size, uint64_t value, void *user_data)
{
    #ifdef DEBUG
        printf_debug("hook_mem_read_after. Address: %" PRIx64 "\n",address);
    #endif
    current_run_state_t *current_run_state=(current_run_state_t *)user_data;

    fprintf(current_run_state->file_fprintf, "\t\t\t\t\t\t\t\t\t\t\t\t >> Hooks: Mem read.  Address: 0x%08" PRIx64 ". Size of read:  %llu Value: 0x%08" PRIx64 " \n",address, size, value);
    return true;
}

bool hook_mem_write(uc_engine *uc, uc_mem_type type, uint64_t address, uint64_t  size, uint64_t value, void *user_data)
{
    #ifdef DEBUG
        printf_debug("hook_mem_write. Address: %" PRIx64 "\n",address);
    #endif

    current_run_state_t *current_run_state=(current_run_state_t *)user_data;
    fprintf(current_run_state->file_fprintf, "\t\t\t\t\t\t\t\t\t\t\t\t >> Hooks: Mem write. Address: 0x%08" PRIx64 ". Size of write: %llu Value: 0x%08" PRIx64 " \n", address, size, value);

    return true;
}
