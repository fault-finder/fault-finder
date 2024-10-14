#include <capstone/capstone.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "unicorn_engine.h"
#include "unicorn_consts.h"
#include "structs.h"
#include "fileio.h"
#include "utils.h"
#include "configuration.h"

void my_uc_context_save(uc_engine *uc,  uc_context* the_context)
{
    uc_err err=uc_context_save(uc, the_context);
    // printf_verbose("Save. Context pointer: %p. Size: %li\n",the_context,context_size(the_context));
    if (err != UC_ERR_OK)
    {
        fprintf(stderr,"Unable to save the context %u: %s\n", err, uc_strerror(err));
        my_exit(-1);
    }

    // If you need to check the contexts are actually correct - they can be saved to file. See next line.
    // save_context_to_file(uc, the_context,"otter-saved.bin"); 
}

void my_uc_context_alloc(uc_engine *uc,  uc_context** the_context)
{
    uc_err err=uc_context_alloc(uc, the_context);
    // printf_verbose("Alloc. Context pointer: %p. Size: %li\n",*the_context,context_size(*the_context));
    // The line above does a malloc somewhere in there! ^^^

    if (err != UC_ERR_OK)
    {
        fprintf(stderr,"Unable to alloc the context %u: %s\n", err, uc_strerror(err));
        my_exit(-1);
    }
}




void save_checkpoint(uc_engine *uc,   current_run_state_t* current_run_state, uint64_t address, uint64_t num)
{
    // alloc the space for the content

    my_uc_context_alloc(uc, &current_run_state->line_details_array[num].the_context);
    
    /// Save the context (registers) to the array
    my_uc_context_save(uc, current_run_state->line_details_array[num].the_context);


    current_run_state->line_details_array[num].stack=my_malloc(binary_file_details->stack.size,"line_details_array - stack");
    uc_err err=uc_mem_read(uc, binary_file_details->stack.address, current_run_state->line_details_array[num].stack, binary_file_details->stack.size);
    if (err != UC_ERR_OK)
    {
        fprintf(stderr,"Unable to read and save the stack %u: %s\n", err, uc_strerror(err));
        my_exit(-1);
    }
    current_run_state->line_details_array[num].memory_main=my_malloc(binary_file_details->memory_main.size,"line_details_array - memory main");
    err=uc_mem_read(uc, binary_file_details->memory_main.address, current_run_state->line_details_array[num].memory_main, binary_file_details->memory_main.size);
    if (err != UC_ERR_OK)
    {
        fprintf(stderr,"Unable to read and save main memory %u: %s\n", err, uc_strerror(err));
        my_exit(-1);
    }
    
    current_run_state->line_details_array[num].memory_other=my_malloc (sizeof(uint8_t*)*binary_file_details->memory_other_count,"line_details_array - memory other pointer");
    for (uint64_t i=0;i<binary_file_details->memory_other_count;i++)
    {
        //save the other memory bits
        current_run_state->line_details_array[num].memory_other[i]=my_malloc ( binary_file_details->memory_other[i].size, "line_details_array - memory other");
        err=uc_mem_read(uc, binary_file_details->memory_other[i].address, current_run_state->line_details_array[num].memory_other[i], binary_file_details->memory_other[i].size);
        if (err != UC_ERR_OK)
        {
            fprintf(stderr,"Unable to read and save other memory %u: %s\n", err, uc_strerror(err));
            my_exit(-1);
        }
    }

    printf_output("Saved a checkpoint: 0x%" PRIx64 ". Count: %lli\n",address,num);
}

void convertToUppercase(char *givenStr)
{
    int i;
    for (i = 0; givenStr[i] != '\0'; i++)
    {
        if (givenStr[i] >= 'a' && givenStr[i] <= 'z')
        {
            givenStr[i] = givenStr[i] - 32;
        }
    }
}


void hook_code_stats(uc_engine *uc, uint64_t address, uint64_t size, void *user_data)
{
    #ifdef DEBUG
        printf_debug("hook_code_stats. Address 0x%" PRIx64 "\n",address);
    #endif
    current_run_state_t* current_run_state=(current_run_state_t*)user_data; 
    uint64_t num=current_run_state->instruction_count;
    if (current_run_state->in_fault_range == 0)
    {
        return;
    }
    #ifdef DEBUG
        printf_debug("hook_code_stats - in faulting range. Address: 0x%" PRIx64 "\n",address);
    #endif
    /// Save the address to the array 
    current_run_state->line_details_array[num].address=address;

    if ((binary_file_details->my_uc_arch == UC_ARCH_ARM    || binary_file_details->my_uc_arch == UC_ARCH_ARM64)) 
    {
        // THIS IS SUCH A HACK! This is a thumb instruction so we need the first bit to be 1 if we restore the checkpoints.
        #ifdef DEBUG
            printf_debug("adding one to the address 0x%" PRIx64 "\n",address);
        #endif
        current_run_state->line_details_array[num].address=address+1;
    }

    current_run_state->line_details_array[num].hit_count=address_hit(current_run_state->address_hit_counter,address);
    current_run_state->line_details_array[num].size=size;
    // Only do this if we're going to use the checkpoints (it's very memory heavvvvy with lots of checkpoints)
    if (current_run_state->start_from_checkpoint == 1 &&  current_run_state->line_details_array[num].checkpoint == true)
    {
        save_checkpoint(uc,current_run_state, address, num);
    }

    if (binary_file_details->my_cs_arch != MY_CS_ARCH_NONE)
    {
        /******** USING CAPSTONE HERE START ************/
        csh handle;
        // Use capstone to dissemble the opcodes
        if (cs_open(binary_file_details->my_cs_arch, binary_file_details->my_cs_mode, &handle) != CS_ERR_OK)
        {   
            fprintf(current_run_state->file_fprintf,"Unable to open (initialise?) capstone.\n");
        }   
        else
        {
            uint8_t* tmp=MY_STACK_ALLOC(size * sizeof(uint8_t));
            // Read the line of code (opcode)
            if (!uc_mem_read(uc, address, tmp, size)) 
            {
                uint128_t current_registers_used=0;  // This will be the bit array for each of the registers

                cs_insn *insn;
                // Now disassemble this line using capstone and display the mnemonics
                size_t count=cs_disasm(handle, tmp, size,0x1000,0, &insn);
                if (count >0)
                {
                    char this_op_str[192];
                    // Count should be 1 as we're only disassmbling one single instruction
                    snprintf(current_run_state->line_details_array[num].op_mnemonic,OP_MNEMONIC_MAX_LENGTH,"%s",insn[0].mnemonic);
                    convertToUppercase(insn[0].op_str);
                    // Get the text from the op code - to see which registers are in there and being used at this instruction
                    snprintf(this_op_str,192,"%s",insn[0].op_str);
                    const char* reg;   

                    current_registers_used=0;
                    for (int i=0;i<MAX_REGISTERS;i++)
                    {
                        reg=register_name_from_int(i); 
                        if (strstr(this_op_str,reg) != NULL)
                        {
                            // set the bit - the op code appears in this instruction
                            set_bit(&current_registers_used,i);
                        }
                    }
                    #ifdef DEBUG
                        printf_debug("current_registers_used %" PRIx64 "\n",current_registers_used);
                    #endif
                }
                else
                {
                    #ifdef DEBUG
                        printf_debug("Unable to disassemble.  %" PRIx64 ". \n",current_registers_used);
                    #endif 
                }
                cs_free (insn,count);
                current_run_state->line_details_array[num].the_registers_used=current_registers_used;

            } 
            else
            {
                fprintf(stderr, "Unable to read from address: 0x%" PRIx64 " size: 0x%" PRIx64 ". \n", address,size);
                my_exit(-1);
            }
        }
        cs_close(&handle);
        /******** USING CAPSTONE HERE END ************/
    }
    else
    {
            /******** Not using any disassembly START ************/
            current_run_state->line_details_array[num].the_registers_used=0xFFFFFFFFFFFFFFFF;
           /******** Not using any disassembly END ************/
    }
}
