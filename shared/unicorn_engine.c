#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <stdbool.h>
#include <inttypes.h>
#include <time.h>
#include "unicorn_engine.h"
#include "utils.h"
#include "unicorn_consts.h"
#include "structs.h"
#include "fileio.h"
#include "configuration.h"
#define SKIP_CHECKING_RETURN_FROM_SET_CPU_MODEL

void my_uc_emu_stop(uc_engine* uc)
{
    uc_err err=uc_emu_stop(uc);
    if (err != UC_ERR_OK)
    {
        fprintf(stderr,"Unable to stop unicorn emulation.\n");
        my_exit(-1);
    }
}

void my_uc_hook_del(const char *function_name,uc_engine *uc, uc_hook hh, current_run_state_t *current_run_state)
{
    #ifdef DEBUG
        printf_debug("my_uc_hook_del. uc_hook: %" PRIx64 ", %s \n", hh,function_name);
    #endif

    uc_err err=uc_hook_del(uc, hh);
    if (err != UC_ERR_OK)
    {
        fprintf(stderr, "Unable to delete hook: %u: %s\n", err, uc_strerror(err));
        my_exit(-1);
    }
}

void my_uc_hook_add(const char *function_name, uc_engine *uc, uc_hook *hh, int type, void *callback,
                      void *user_data, uint64_t begin, uint64_t end)
{

    uc_err err=uc_hook_add(uc, hh, type, callback, user_data, begin, end);
    if (err != UC_ERR_OK)
    {
        fprintf(stderr, "Unable to add hook: %s %u: %s\n", function_name, err, uc_strerror(err));
        my_exit(-1);
    }

#ifdef DEBUG
    printf_debug("my_uc_hook_add. uc_hook: %" PRIx64 ", %s - 0x%" PRIx64 " 0x%" PRIx64 "\n", *hh, function_name, begin, end);
#endif
}

void my_uc_context_restore(uc_engine *uc,  uc_context* the_context)
{
    uc_err err=0;
    // printf_verbose("Restore. Context pointer: %p. Size: %li\n",the_context,context_size(the_context));
    err=uc_context_restore(uc, the_context);

    if (err != UC_ERR_OK)
    {
        fprintf(stderr, "Unable to restore the context %u: %s\n", err, uc_strerror(err));
        my_exit(-1);
    }
    // For checking the contexts.
    // save_context_to_file(uc, the_context,"otter-restored.bin"); //verbose

}

void uc_restore_from_checkpoint(uc_engine *uc, current_run_state_t *current_run_state, uint64_t instr)
{
    #ifdef DEBUG
        printf_debug("uc_restore_from_checkpoint. Instruction %li\n",instr);
    #endif

    /*  
    If 'checkpoints' are used - then this function is where the checkpoint is restored
    We need to restore: context, main memory, stack and other memory and reset the program counter register
    */
    uint64_t checkpoint_instr=current_run_state->line_details_array[instr].nearest_checkpoint;
    uint64_t address=current_run_state->line_details_array[instr].address;
    
    fprintf_output( current_run_state->file_fprintf,
                    "Restoring check point. Starting from: %llu Address: 0x%" PRIx64 " . (Checkpoint: %llu Address: 0x%" PRIx64 ") \n", 
                    instr, 
                    address,
                    checkpoint_instr,
                    current_run_state->line_details_array[checkpoint_instr].address);

    if (current_run_state->line_details_array[checkpoint_instr].the_context == NULL)
    {
        fprintf(stderr, "Unable to restore from checkpoint instruction %llu. No checkpoint stored. (Actual instruction: %llu)\n", checkpoint_instr,instr);
        my_exit(-1);
    }

    if (current_run_state->line_details_array[checkpoint_instr].checkpoint == false)
    {
        fprintf(stderr, "Checkpoint instruction %llu is reporting itself NOT to be a checkpoint! (Actual instruction: %llu)\n", checkpoint_instr,instr);
        my_exit(-1);
    }


    uc_err err;
    my_uc_context_restore(uc, current_run_state->line_details_array[checkpoint_instr].the_context);


    //RESTORE THE STACK
    #ifdef DEBUG
        printf_debug("Rewriting the stack. Address: 0x%lx. Size: 0x%lx \n", binary_file_details->stack.address,binary_file_details->stack.size);
    #endif

    err=uc_mem_write(uc, binary_file_details->stack.address, current_run_state->line_details_array[checkpoint_instr].stack, binary_file_details->stack.size);
    if (err != UC_ERR_OK)
    {
        fprintf(stderr, "Unable to restore the stack %u: %s\n", err, uc_strerror(err));
        my_exit(-1);
    }

     //RESTORE THE Main memory
    #ifdef DEBUG
        printf_debug("Rewriting the main meory. Address: 0x%lx. Size: 0x%lx \n", binary_file_details->memory_main.address,binary_file_details->memory_main.size);
    #endif
    err=uc_mem_write(uc, binary_file_details->memory_main.address, current_run_state->line_details_array[checkpoint_instr].memory_main, binary_file_details->memory_main.size);
    if (err != UC_ERR_OK)
    {
        fprintf(stderr, "Unable to restore main memory %u: %s\n", err, uc_strerror(err));
        my_exit(-1);
    }

    //RESTORE other memory
    for (uint64_t i=0;i<binary_file_details->memory_other_count;i++)
    {
    #ifdef DEBUG
        printf_debug("Rewriting other memory. Address: 0x%lx. Size: 0x%lx \n", binary_file_details->memory_other[i].address,binary_file_details->memory_other[i].size);
    #endif
        err=uc_mem_write(uc, binary_file_details->memory_other[i].address, current_run_state->line_details_array[checkpoint_instr].memory_other[i], binary_file_details->memory_other[i].size);
        if (err != UC_ERR_OK)
        {
            fprintf(stderr,"Unable to restore other memory %u: %s\n", err, uc_strerror(err));
            my_exit(-1);
        }
    }

    // uint64_t tmp_reg=0;
    // uc_reg_read(uc, binary_file_details->my_pc_reg, &tmp_reg);

    // // if thumb
    // if ((binary_file_details->my_uc_arch == UC_ARCH_ARM || binary_file_details->my_uc_arch == UC_ARCH_ARM64))
    // {
    //     #ifdef DEBUG
    //         printf_debug("uc_restore_from_checkpoint. Adding one to program counter. 0x%llu\n",tmp_reg);
    //     #endif
    //     tmp_reg++;  // IF THUMB
    // }

    if (current_run_state->hk_count_instructions == 0)
    { 
        my_uc_hook_add("hk_count_instructions", uc, &current_run_state->hk_count_instructions, UC_HOOK_CODE, hook_count_instructions, current_run_state, 1, 0);
    }
    current_run_state->instruction_count=checkpoint_instr ;     // Jump to the instruction
    current_run_state->in_fault_range=1;
    current_run_state->run_state=STARTED_FROM_CHECKPOINT_rs;

    // stop emulation
    #ifdef DEBUG
            printf_debug("uc_restore_from_checkpoint. Adding one to program counter. 0x%llu\n",current_run_state->line_details_array[checkpoint_instr].address);
        #endif
    current_run_state->restart=true;
    current_run_state->restart_address=current_run_state->line_details_array[checkpoint_instr].address;
    my_uc_emu_stop(uc);
}

void print_sp_and_pc(uc_engine *uc, current_run_state_t *current_run_state)
{
    uint64_t tmp_reg={0};
    uc_err err;

    err=uc_reg_read(uc, binary_file_details->my_sp_reg, &tmp_reg);
    if (err != UC_ERR_OK)
    {
        fprintf(stderr, "Failed to read program counter contents. Error: %s\n", uc_strerror(err));
        my_exit(-1);
    }
    printf_debug("Stack Pointer: 0x%" PRIx64 " \n", tmp_reg);

    err=uc_reg_read(uc, binary_file_details->my_pc_reg, &tmp_reg);
    if (err != UC_ERR_OK)
    {
        fprintf(stderr, "Failed to read stack pointer contents. Error: %s\n", uc_strerror(err));
        my_exit(-1);
    }
    printf_debug("Program Counter: 0x%" PRIx64 "\n", tmp_reg);
}


void print_outputs(uc_engine *uc, current_run_state_t *current_run_state)
{
#ifdef DEBUG
    printf_debug("print_outputs\n");
#endif
    uc_err err;
    uint64_t len;
    FILE* f = current_run_state->file_fprintf;

    for (uint64_t i=0; i < binary_file_details->outputs_count; i++)
    {
        if (binary_file_details->outputs[i].location == address_in_register_loc)
        {
            uint64_t tmp_address=0;
            uint64_t tmp_reg = binary_file_details->outputs[i].reg;
            err=uc_reg_read(uc, uc_reg_from_int(tmp_reg), &tmp_address);
            if (err == UC_ERR_OK)
            {
                fprintf(f, " >>> Output from address (0x%08llx) in register (%s) : ", tmp_address, register_name_from_int(tmp_reg));
                len =binary_file_details->outputs[i].length;
                uint8_t* tmp_output=MY_STACK_ALLOC(len +1);
                err=uc_mem_read(uc, tmp_address, tmp_output, binary_file_details->outputs[i].length);
                if (err == UC_ERR_OK)
                {
                    phex(f, tmp_output,len);
                }
                else
                {
                    fprintf (f,"Unable to read memory address: 0x%" PRIx64 "\n",tmp_address);
                }
            }
            else
            {
                fprintf (f,"Unable to read from register: %s\n", register_name_from_int(tmp_reg));
            }
        }
        else if ((binary_file_details->outputs[i].location == relative_address_loc) || (binary_file_details->outputs[i].location == fixed_address_loc))
        {
            uint64_t tmp_address=binary_file_details->outputs[i].address;
            if (binary_file_details->outputs[i].location == relative_address_loc)
            {
                // Add the memory base if it is a relative adddress
                tmp_address +=binary_file_details->memory_main.address;
            }
            len=binary_file_details->outputs[i].length;
            uint8_t* tmp_output=MY_STACK_ALLOC(len+1);
            err=uc_mem_read(uc, tmp_address, (void*)tmp_output, len);
            if (err == UC_ERR_OK)
            {
                fprintf(f," >>> Output from address (0x%08llx): ", tmp_address);
                phex(f, tmp_output,len);
            }
            else
            {
                fprintf(stderr, "Unable to read memory address: %" PRIx64 " Error %s\n", tmp_address, uc_strerror(err));
            }
        }
        else if (binary_file_details->outputs[i].location == register_loc)
        {
            uint64_t tmp_val=0;
            uint64_t tmp_reg = binary_file_details->outputs[i].reg;
            fprintf(f, " >>> Output from register (%s): ", register_name_from_int(tmp_reg));
            err=uc_reg_read(uc, uc_reg_from_int(tmp_reg), &tmp_val);
            if (err == UC_ERR_OK)
            {
                fprintf(f, "0x%" PRIx64 ".\n", tmp_val);
            }
        }
        else
        {
            fprintf(stderr, "No valid final result location found\n");
            my_exit(-1);
        }
        if (err != UC_ERR_OK)
        {
            fprintf(f, " >>> Unable to read output %02llu: \n", i);
        }
    }

}

void uc_engine_set_memory_inputs(uc_engine *uc, current_run_state_t *current_run_state)
{
    uint64_t new_address=0;
    uc_err err;
    FILE *fd=current_run_state->file_fprintf;
#ifdef DEBUG
    printf_debug("uc_engine_set_memory_inputs.\n");
#endif

    for (uint64_t i=0; i < binary_file_details->set_memory_count; i++)
    {
        if (binary_file_details->set_memory[i].type == address_memory)
        {
            new_address=binary_file_details->set_memory[i].address;
            fprintf_output(fd, "Writing memory input #%llu directly to address: 0x%016llx: ", i,new_address);
            phex(fd,binary_file_details->set_memory[i].byte_array, binary_file_details->set_memory[i].length);

        }
        else
        {
            // get sp value
            err=uc_reg_read(uc, binary_file_details->my_sp_reg, &new_address);
            if (err != UC_ERR_OK)
            {   
                fprintf(stderr, "Failed to read sp contents. Error: %s\n", uc_strerror(err));
                my_exit(-1);
            }
            new_address=new_address+binary_file_details->set_memory[i].sp_offset;
            #ifdef DEBUG
                fprintf(fd, " >> Writing memory input  #%llu : Sp offset: %llu (decimal) - address: 0x%016li: ", i,
                        (int64_t)binary_file_details->set_memory[i].sp_offset, new_address);
            #endif
        }

        err=uc_mem_write(uc,
                        new_address,
                        binary_file_details->set_memory[i].byte_array,
                        binary_file_details->set_memory[i].length);
        if (err != UC_ERR_OK)
        {
            fprintf(stderr, "Failed to write input %llu to address: 0x%" PRIx64 ". Error: %s\n", i, binary_file_details->set_memory[i].address, uc_strerror(err));
            fprintf(stderr, "Check you are using 0x to represent a hex address?");
            my_exit(-1);
        }
    }
}

void uc_engine_set_new_register_inputs(uc_engine *uc, current_run_state_t *current_run_state)
{
    uc_err err;
    uint64_t reg_tmp=0,value=0;
    FILE *fd=current_run_state->file_fprintf;
    for (uint64_t i=0; i < binary_file_details->set_registers_count; i++)
    {
        reg_tmp=binary_file_details->set_registers[i].reg;
        value=binary_file_details->set_registers[i].reg_value;
        fprintf(fd, " >> Writing register input #%llu directly to register: %s. Value: 0x%016llx\n", i, register_name_from_int(reg_tmp),value);

        err=uc_reg_write(uc,uc_reg_from_int(reg_tmp), &value);
        if (err != UC_ERR_OK)
        {
            fprintf(stderr, "Failed to write register input %llu to register:%llu. Error: %s\n", i, reg_tmp, uc_strerror(err));
            my_exit(-1);
        }
    }
}

void uc_engine_load_code_into_memory(uc_engine *uc, const char *code_buffer, size_t filesize)
{
    #ifdef DEBUG
        printf_debug("writing code into memory:\n");
        printf_debug("memory_main.address: 0x%" PRIx64 "\n",binary_file_details->memory_main.address);
        printf_debug("code_buffer: %s \n",code_buffer);
        printf_debug("code_offset: 0x%" PRIx64 "\n",binary_file_details->code_offset);
        printf_debug("filesize: 0x%" PRIx64 ", (%llu) bytes\n",filesize,filesize);
    #endif
    uc_err err=uc_mem_write(uc, binary_file_details->memory_main.address,
                                code_buffer + binary_file_details->code_offset,
                                filesize - binary_file_details->code_offset);

    if (err != UC_ERR_OK)
    {
        fprintf(stderr, "Failed to write code to memory, quit!\n");
        fprintf(stderr, "Tried to write:\n");
        fprintf(stderr, "\t memory_main.address: 0x%" PRIx64 "\n",binary_file_details->memory_main.address);
        fprintf(stderr, "\t code_buffer: %s\n",code_buffer);
        fprintf(stderr, "\t code_offset: 0x%" PRIx64 "\n",binary_file_details->code_offset);
        fprintf(stderr, "\t filesize: 0x%016zx, (%zu) bytes\n",filesize,filesize);
        fprintf(stderr, "\t memory_main.size: 0x%" PRIx64 " bytes\n",binary_file_details->memory_main.size);
        my_exit(-1);
    }
}
void current_run_state_init(current_run_state_t* current_run_state)
{
#ifdef DEBUG
    printf_debug("current_run_state_init - all hooks set to zero.\n");
#endif
#ifdef SKIP_CHECKING_RETURN_FROM_SET_CPU_MODEL
    printf("WARNING: We are not checking the return "
           "value from set cpu model, because it errors on Tricore for some "
           "reason\n");
#endif
    current_run_state->directory=0;
    current_run_state->run_mode=eNONE_rm;
    current_run_state->run_state=NONE_rs;
    current_run_state->fault_instruction_min=0;
    current_run_state->fault_instruction_max=0;
    current_run_state->instruction_count=0;
    current_run_state->total_instruction_count=0;
    current_run_state->last_address=0;
    current_run_state->in_fault_range=0;
    current_run_state->hk_start_faults=0;
    current_run_state->hk_stop_faults=0;
    current_run_state->hk_start_address=0;
    current_run_state->hk_end_address=0;
    current_run_state->hk_skips=0;  
    current_run_state->hk_count_instructions=0;
    current_run_state->hk_fault_address=0;
    current_run_state->hk_fault_it=0;
    current_run_state->hk_intr=0;
    current_run_state->hk_insn=0; 
    current_run_state->hk_print_instructions=0;
    current_run_state->hk_hard_stops=0; 
    current_run_state->hk_memory_invalid=0;
    current_run_state->hk_instruction_invalid=0;
    current_run_state->hk_fault_lifespan=0;
    current_run_state->hk_equivalent=0;
    current_run_state->start_from_checkpoint=0;
    current_run_state->stop_on_equivalence=0;
    current_run_state->max_instructions=0;
    current_run_state->display_disassembly=0;
    current_run_state->timeit=0;
    current_run_state->address_hit_counter=0;
    current_run_state->my_function_list.head=0;
    current_run_state->my_function_list.tail=0;
    current_run_state->restart=0;
    current_run_state->restart_address=0;
    current_run_state->addresses_and_disassembly_from_file=0;
    current_run_state->addresses_and_disassembly_from_file_count=0;
}

void current_run_state_reset(current_run_state_t* current_run_state)
{
#ifdef DEBUG
    printf_debug("current_run_state_reset - instruction_count=0.\n");
    printf_debug("current_run_state_reset - in_fault_range=0.\n");
    printf_debug("current_run_state_reset - last_address=0.\n");
    printf_debug("current_run_state_reset - run_state=NONE_rs.\n");
#endif
    current_run_state->instruction_count=0;
    current_run_state->in_fault_range=0;
    current_run_state->last_address=0;
    current_run_state->run_state=NONE_rs;
}


void uc_engine_set_memory_to_zeros(uc_engine* uc)
{
#ifdef DEBUG
    printf_debug("uc_engine_set_memory_to_zeros - setting memory locations to zeros.\n");
#endif
  // Reset out the stack

    char *tmp_mem=MY_STACK_ALLOC(binary_file_details->stack.size);
    if (tmp_mem == NULL)
    {
        fprintf(stderr, "Unable to allocate memory on the stack of size: %llu for temporary stack memory\n",binary_file_details->stack.size);
    }
    memset(tmp_mem, 0, binary_file_details->stack.size);
    if (uc_mem_write(uc, binary_file_details->stack.address, tmp_mem, binary_file_details->stack.size))
    {
        fprintf(stderr, "Failed to clean stack, quit!\n");
        my_exit(-1);
    }

    //reset main memory
    tmp_mem=MY_STACK_ALLOC(binary_file_details->memory_main.size);
    if (tmp_mem == NULL)
    {
        fprintf(stderr, "Unable to allocate memory on the stack of size: %llu for temporary main memory\n",binary_file_details->memory_main.size);
    }
    memset(tmp_mem, 0, binary_file_details->memory_main.size);
    if (uc_mem_write(uc, binary_file_details->memory_main.address, tmp_mem, binary_file_details->memory_main.size))
    {
        fprintf(stderr, "Failed to clean main memory, quit!\n");
        my_exit(-1);
    }
    //reset other memory
    for (int i=0;i< binary_file_details->memory_other_count;i++)
    {
        tmp_mem=MY_STACK_ALLOC(binary_file_details->memory_other[i].size);
        if (tmp_mem == NULL)
        {
            fprintf(stderr, "Unable to allocate memory on the stack of size: %llu for temporary other memory\n",binary_file_details->memory_other[i].size);
        }
        memset(tmp_mem, 0, binary_file_details->memory_other[i].size);
        if (uc_mem_write(uc, binary_file_details->memory_other[i].address, tmp_mem, binary_file_details->memory_other[i].size))
        {
            fprintf(stderr, "Failed to clean other memory[%i], quit!\n",i);
            my_exit(-1);
        }
    }
}


void uc_engine_init_SP(uc_engine *uc, current_run_state_t *current_run_state)
{

   // // set up the stack pointer
    uint64_t sp=binary_file_details->stack_start_address;

#ifdef DEBUG
    printf_debug("uc_engine_init_SP - reseting stack pointer to 0x%" PRIx64 "\n",sp);
#endif
    uc_err err=uc_reg_write(uc, binary_file_details->my_sp_reg, &sp);
    if (err != UC_ERR_OK)
    {
        fprintf(stderr, "Failed on uc_reg_write() for sp with error returned: %s\n", uc_strerror(err));
        my_exit(-1);
    }
}
void uc_engine_hooks_reset(uc_engine *uc, current_run_state_t *current_run_state)
{
    // If the run crashes it may not have deleted the hooks correctly.
#ifdef DEBUG
    printf_debug("uc_engine_hooks_reset - checking hooks are deleted\n");
#endif
    delete_hook_count_instructions(uc, current_run_state);
    if (current_run_state->hk_equivalent != 0)
    {
        my_uc_hook_del("hk_equivalent",uc,current_run_state->hk_equivalent,current_run_state);
        current_run_state->hk_equivalent=0;
    }
    if (current_run_state->hk_fault_address != 0)
    {
        my_uc_hook_del("hk_fault_address",uc,current_run_state->hk_fault_address,current_run_state);
        current_run_state->hk_fault_address=0;
    }
    if (current_run_state->hk_fault_it != 0)
    {
        my_uc_hook_del("hk_fault_it",uc,current_run_state->hk_fault_it,current_run_state);
        current_run_state->hk_fault_it=0;
    }
    if (current_run_state->hk_fault_lifespan != 0)
    {
        my_uc_hook_del("hk_fault_lifespan",uc,current_run_state->hk_fault_lifespan,current_run_state);
        current_run_state->hk_fault_lifespan=0;
    }
}

void my_uc_engine_reset(uc_engine *uc, current_run_state_t *current_run_state)
{
    uc_engine_hooks_reset(uc,current_run_state);
    
#ifdef DEBUG
    printf_debug("my_uc_engine_reset\n");
    printf_debug("memory writing: 0x%" PRIx64 ", memory size: 0x%" PRIx64 " \n", binary_file_details->memory_main.address, binary_file_details->memory_main.size);
#endif
    
    uc_engine_set_memory_to_zeros(uc);
    uc_engine_load_code_into_memory(uc, binary_file_details->code_buffer ,binary_file_details->code_buffer_size);
    uc_engine_set_memory_inputs(uc, current_run_state);   
    uc_engine_init_SP(uc,current_run_state);
}

void my_uc_mem_map(uc_engine *uc, uint64_t address, size_t size, uint32_t perms,char* desc)
{
    // printf_verbose("uc_mem_map: Address: 0x%" PRIx64 ",  size: 0x%" PRIx64 " %s \n", address,size,desc);
    #ifdef DEBUG
        printf_debug("uc_mem_map: Address: 0x%" PRIx64 ",  size: 0x%" PRIx64 "\n", address,size);
    #endif

    uc_err err=uc_mem_map(uc, address, size, perms);
    if (err != UC_ERR_OK)
    {
        fprintf(stderr, "Failed on uc_mem_map() for with error returned: %s\n", uc_strerror(err));
        fprintf(stderr, "\t Address: 0x%" PRIx64 "\n", address);
        fprintf(stderr, "\t Size   : 0x%0zx\n", size);
        fprintf(stderr, "Possible reasons include: overlapping memory regions or too small size.\n");
        my_exit(-1);
    }
}

void uc_engine_open_and_mem_map(uc_engine **uc,current_run_state_t* current_run_state,char* desc)
{

    uc_err err = uc_open(binary_file_details->my_uc_arch, binary_file_details->my_uc_mode, uc);
    
    // printf_verbose("OPEN OPEN OPEN: %s %p\n",desc,*uc);
    
#ifdef DEBUG
    printf_debug("uc_engine_open_and_mem_map. uc: %p\n",*uc);
#endif
    if (err != UC_ERR_OK)
    {
        fprintf(stderr, "Failed on uc_open() with error returned: %s\n", uc_strerror(err));
        fprintf(stderr, "Architecture: %s (%d) and mode: %s (%d) \n",
            unicorn_arch_name_from_int(binary_file_details->my_uc_arch), 
            binary_file_details->my_uc_arch, 
            unicorn_mode_name_from_int(binary_file_details->my_uc_mode),
            binary_file_details->my_uc_mode); 
        my_exit(-1);
    }


    err = uc_ctl_set_cpu_model(*uc, binary_file_details->my_uc_cpu);
    #ifndef SKIP_CHECKING_RETURN_FROM_SET_CPU_MODEL
    if (err != UC_ERR_OK)
    {
        fprintf(stderr, "Failed on uc_ctl_set_cpu_model() with error returned: %s\n", uc_strerror(err));
        my_exit(-1);
    }

    #endif
    // STACK
    my_uc_mem_map(*uc, binary_file_details->stack.address, binary_file_details->stack.size, UC_PROT_ALL,desc);

    // MAIN MEMORY
    my_uc_mem_map(*uc, binary_file_details->memory_main.address, binary_file_details->memory_main.size, UC_PROT_ALL,desc);
    
    // MAIN OTHER REGIONS
    for (int i=0; i<binary_file_details->memory_other_count; i++)
    {
        my_uc_mem_map(*uc, binary_file_details->memory_other[i].address, binary_file_details->memory_other[i].size, UC_PROT_ALL,desc);
    }


    // make the space for the hard stop hooks
    if (binary_file_details->hard_stops_count>0)
    {
        current_run_state->hk_hard_stops=my_malloc(sizeof(uc_hook)*binary_file_details->hard_stops_count,"hk_hard_stops");
    }

    // make the space for the skip hooks
    if (binary_file_details->skips_count>0)
    {
        current_run_state->hk_skips=my_malloc(sizeof(uc_hook)*binary_file_details->skips_count,"hk_skips");
    }

}



void uc_engine_create_hooks(uc_engine *uc, current_run_state_t *current_run_state)
{
    #ifdef DEBUG
        printf_debug("uc_engine_create_hooks\n");
    #endif
    my_uc_hook_add("hk_intr", uc, &current_run_state->hk_intr, UC_HOOK_INTR, hook_intr, current_run_state, 1, 0); //(Does this do anything?)

    // 1 << 4,5,6,7,8,9
    my_uc_hook_add("hk_memory_invalid", uc, &current_run_state->hk_memory_invalid, UC_HOOK_MEM_INVALID, hook_memory_invalid, current_run_state, 1, 0);
    my_uc_hook_add("hk_instruction_invalid", uc, &current_run_state->hk_instruction_invalid, UC_HOOK_INSN_INVALID, hook_instruction_invalid, current_run_state, 1, 0);

    my_uc_hook_add("hk_end_address", uc, &current_run_state->hk_end_address, UC_HOOK_CODE, hook_code_end_address, 
        current_run_state, 
        binary_file_details->code_end_address,
        binary_file_details->code_end_address);
    uint64_t start_address= thumb_check_address(binary_file_details->code_start_address); 

    my_uc_hook_add("hk_start_address", uc, &current_run_state->hk_start_address, UC_HOOK_CODE, hook_code_start_address, 
        current_run_state, 
        start_address,
        start_address);

    // Add hooks for skipping instructions that the engine can't run e.g. printf!
    for (uint64_t i = 0; i < binary_file_details->skips_count; i++)
    {
      uint64_t addr = binary_file_details->skips[i].address;
      addr += binary_file_details->memory_main.address;
      my_uc_hook_add("hk_skips",uc, 
            &current_run_state->hk_skips[i], UC_HOOK_CODE, 
            hook_code_skips, 
            current_run_state, 
		     addr,
		     addr);
    }

    // start and end hooks
    my_uc_hook_add("hk_start_faults",uc, &current_run_state->hk_start_faults, UC_HOOK_CODE, hook_code_start_faults, 
        current_run_state, 
        binary_file_details->fault_start_address , 
        binary_file_details->fault_start_address );
        
    my_uc_hook_add("hk_stop_faults",uc, &current_run_state->hk_stop_faults, UC_HOOK_CODE, hook_code_stop_faults, 
        current_run_state, 
        binary_file_details->fault_end_address,
        binary_file_details->fault_end_address);

    #ifdef PRINTINSTRUCTIONS
        my_uc_hook_add("hk_print_instructions",uc, &current_run_state->hk_print_instructions, UC_HOOK_CODE, hook_code_print_instructions, current_run_state,1,0);
    #endif

    // Hard stops - areas of the program that you shouldn't get to without a fault.
    for (int i=0;i<binary_file_details->hard_stops_count;i++)
    {
	hard_stops_t *hs = &binary_file_details->hard_stops[i];
        uint64_t addr = hs->address;
        if (hs->location != fixed_address_loc)
	{
	    addr += binary_file_details->memory_main.address;
	}
        my_uc_hook_add("hk_hard_stops", uc,
                       &current_run_state->hk_hard_stops[i], UC_HOOK_CODE,
                       hook_code_hard_stop, current_run_state, addr, addr);
    }
}

void uc_engine_insert_patches(uc_engine *uc,current_run_state_t* current_run_state)
{
   // Overwrite memory for patching instructions that the engine can't run e.g. printf!
    for (uint64_t i=0; i < binary_file_details->patches_count; i++)
    {
        uint64_t address_patch = binary_file_details->patches[i].address + binary_file_details->memory_main.address;
        fprintf_output(current_run_state->file_fprintf, "Patching instruction:0x%" PRIx64 "\n",address_patch);
        uc_err err = uc_mem_write(uc, address_patch ,binary_file_details->patches[i].byte_array,binary_file_details->patches[i].length);
        if (err != UC_ERR_OK)
        {
            fprintf(stderr, "Unable to write the patched instruction: 0x%" PRIx64 ". %s\n",address_patch, uc_strerror(err));
            my_exit(-1);
        }
    }
}

void my_uc_engine_setup(uc_engine **uc, current_run_state_t* current_run_state,char* desc)
{
    #ifdef DEBUG
        printf_debug("my_uc_engine_setup\n");
    #endif
    uc_engine_open_and_mem_map(uc,current_run_state,desc);
    uc_engine_create_hooks(*uc,current_run_state);
    uc_engine_load_code_into_memory(*uc, binary_file_details->code_buffer ,binary_file_details->code_buffer_size);
    uc_engine_insert_patches(*uc,current_run_state);

    uc_engine_set_memory_inputs(*uc, current_run_state);  
    uc_engine_set_new_register_inputs(*uc, current_run_state);  
    uc_engine_init_SP(*uc,current_run_state);
}

void print_hooks(uc_engine *uc, current_run_state_t *current_run_state)
{
    printf("Let's print some hooks!\n");

    struct list_item
    {
        struct list_item *next;
        void *data;
    };

    struct list
    {
        struct list_item *head, *tail;
    };

    struct uc_struct_copy
    {
        char padding[0x628];
        struct list hook[14];
    };

    struct uc_struct_copy *uc_temp=(struct uc_struct_copy *)uc;
    for (int i=0; i < 14; i++)
    {
        printf("~~~ Printing hooks %i ~~~\n", i);
        struct list_item *current_uc_hook=uc_temp->hook[i].head;
        while (current_uc_hook)
        {
            printf("\tPrinting hook address: %p. ", current_uc_hook->data);

            function_item_t *current_func=current_run_state->my_function_list.head;
            while (current_func)
            {
                if (current_func->function_hook == (uc_hook)current_uc_hook->data)
                {
                    printf("\tFunction name: %s.\n", current_func->function_name);
                }
                current_func=current_func->next;
            }
            current_uc_hook=current_uc_hook->next;
        }
    }
}



void my_uc_engine_start(uc_engine *uc, current_run_state_t *current_run_state, uint64_t max_instructions)
{
    // RUN IT RUN IT RUN IT. Runs from code_start_address to code_end_address as provided in the defines.json
#ifdef DEBUG
    printf_debug("my_uc_engine_start. Running from 0x%" PRIx64 " to 0x%" PRIx64 ".\n",
        binary_file_details->code_start_address, 
        binary_file_details->code_end_address);
#endif

    uint64_t timeout_val=binary_file_details->timeout;
    if (current_run_state->run_mode != eFAULT_rm) {
        timeout_val=-1;
    }
    /// I'm adding 1 to the end address so that it actually runs the last address too. There is a hook for the code_end_address - hook_code_end_address
    // that tells me that it made it to the end! And then calls uc_emu_stop  (I can't know the address of the instruction AFTER because I don't know how big the last instruction is!
    uc_err err;
    current_run_state->time_to_run=0;
    struct timespec start, stop;

    /* GET TIME FOR START TIME*/
    if (current_run_state->timeit == 1)
    {
        if( clock_gettime(CLOCK_REALTIME, &start) == -1 ) 
        {
            fprintf(stderr,  "Clock gettime failed." );
            my_exit( -1);
        }
    }

    /* run it */
    err = uc_emu_start(uc, binary_file_details->code_start_address,
                       binary_file_details->code_end_address + 1, timeout_val,
                       max_instructions);
    if (err)
    {
        fprintf_errors(current_run_state->file_fprintf, "Failed on uc_emu_start() first run with error returned %u: %s.\n", err, uc_strerror(err));
        current_run_state->run_state=ERRORED_rs;
    }

    while (current_run_state->restart == 1 && current_run_state->run_state != ERRORED_rs)
    { 
        #ifdef DEBUG
            printf_debug("Restarting - from address: 0x%" PRIx64 "\n",current_run_state->restart_address);
        #endif

        // reset the resetart flag - so we don't get stuck in an infinite loop
        current_run_state->restart=0;
        
        err=uc_emu_start(uc, current_run_state->restart_address, binary_file_details->code_end_address + 1, timeout_val, max_instructions);

        if (err)
        {
            fprintf_errors(current_run_state->file_fprintf, "Failed on uc_emu_start() restart with error returned %u: %s.\n", err, uc_strerror(err));
            current_run_state->run_state=ERRORED_rs;
        }
    }

    /* GET TIME FOR STOP TIME*/
    if (current_run_state->timeit == 1)
    {
        if( clock_gettime( CLOCK_REALTIME, &stop) == -1 ) 
        {
            fprintf(stderr, "Clock gettime failed." );
            my_exit( -1 );
        }
        current_run_state->time_to_run=(( stop.tv_sec - start.tv_sec )*BILLION) + ( stop.tv_nsec - start.tv_nsec ) ;
    }

    size_t timeout_question;
    uc_query(uc,UC_QUERY_TIMEOUT,&timeout_question);
    if (timeout_question)
    {
        current_run_state->run_state=TIMED_OUT_rs;
    }
    if (current_run_state->instruction_count != 0)
    {
        current_run_state->instruction_count--; // It will have incremented by 1 before ending (!)
    }
}

void uc_delete_all_hooks(uc_engine *uc,current_run_state_t* current_run_state)
{
    #ifdef DEBUG
        printf_debug("uc_delete_all_hooks\n");
    #endif

    delete_hook_count_instructions(uc, current_run_state);
    if (current_run_state->hk_end_address != 0)
    {
        my_uc_hook_del("hk_end_address",uc, current_run_state->hk_end_address, current_run_state);
        current_run_state->hk_end_address=0;
    }

    if (current_run_state->hk_fault_address != 0)
    {
        my_uc_hook_del("hk_fault_address",uc, current_run_state->hk_fault_address, current_run_state);
        current_run_state->hk_fault_address=0;
    }

    if (current_run_state->hk_fault_it != 0)
    {
        my_uc_hook_del("hk_fault_it",uc, current_run_state->hk_fault_it, current_run_state);
        current_run_state->hk_fault_it=0;
    }

    if (current_run_state->hk_fault_lifespan != 0)
    {
        my_uc_hook_del("hk_fault_lifespan",uc, current_run_state->hk_fault_lifespan, current_run_state);
        current_run_state->hk_fault_lifespan=0;
    }

    for (int i=0;i<binary_file_details->hard_stops_count;i++)
    {
        if (current_run_state->hk_hard_stops[i] != 0)
        {
            my_uc_hook_del("hk_hard_stops",uc, current_run_state->hk_hard_stops[i], current_run_state);
            current_run_state->hk_hard_stops[i]=0;
        }
    }

    if (current_run_state->hk_insn != 0)
    {
        my_uc_hook_del("hk_insn",uc, current_run_state->hk_insn, current_run_state);
        current_run_state->hk_insn=0;
    }
    if (current_run_state->hk_intr != 0)
    {
        my_uc_hook_del("hk_intr",uc, current_run_state->hk_intr, current_run_state);
        current_run_state->hk_intr=0;
    }
    if (current_run_state->hk_memory_invalid != 0)
    {
        my_uc_hook_del("hk_memory_invalid",uc, current_run_state->hk_memory_invalid, current_run_state);
        current_run_state->hk_memory_invalid=0;
    }

    if (current_run_state->hk_instruction_invalid != 0)
    {
        my_uc_hook_del("hk_instruction_invalid",uc, current_run_state->hk_instruction_invalid, current_run_state);
        current_run_state->hk_instruction_invalid=0;
    }
    
    if (current_run_state->hk_print_instructions != 0)
    {
        my_uc_hook_del("hk_print_instructions",uc, current_run_state->hk_print_instructions, current_run_state);
        current_run_state->hk_print_instructions=0;
    }
    for (int i=0;i<binary_file_details->skips_count;i++)
    {
        if (current_run_state->hk_skips[i] != 0)
        {
            my_uc_hook_del("hk_skips",uc, current_run_state->hk_skips[i], current_run_state);
            current_run_state->hk_skips[i]=0;
        }
    }
    if (current_run_state->hk_start_address != 0)
    {
        my_uc_hook_del("hk_start_address",uc, current_run_state->hk_start_address, current_run_state);
        current_run_state->hk_start_address=0;
    }
    if (current_run_state->hk_start_faults != 0)
    {
        my_uc_hook_del("hk_start_faults",uc, current_run_state->hk_start_faults, current_run_state);
        current_run_state->hk_start_faults=0;
    }
    if (current_run_state->hk_stop_faults != 0)
    {
        my_uc_hook_del("hk_stop_faults",uc, current_run_state->hk_stop_faults, current_run_state);
        current_run_state->hk_stop_faults=0;
    }
    if (current_run_state->hk_equivalent != 0)
    {
        my_uc_hook_del("hk_equivalent",uc, current_run_state->hk_equivalent, current_run_state);
        current_run_state->hk_equivalent=0;
    }
    // Remove the malloc'd spaced for the hard stops
    my_free(current_run_state->hk_hard_stops,"hk_hard_stops");
    // Remove the malloc'd spaced for the skips
    my_free(current_run_state->hk_skips,"hk_skips");
}


// void uc_zero_all_memory(uc_engine *uc,current_run_state_t* current_run_state)
// {
// THIS IS NOT CALLED !!!
//     #ifdef DEBUG
//         printf_debug("uc_zero_all_memory\n");
//     #endif

//     // Reset out the stack
//     char *tmp_stack=MY_STACK_ALLOC(binary_file_details->stack.size);
//     memset(tmp_stack, 0, binary_file_details->stack.size);
//     if (uc_mem_write(uc, binary_file_details->stack.address, tmp_stack, binary_file_details->stack.size))
//     {
//         fprintf(stderr, "Failed to clean stack, quit!\n");
//         my_exit(-1);
//     }

//     //reset main memory
//     char* tmp_main_memory=MY_STACK_ALLOC(binary_file_details->memory_main.size);
//     memset(tmp_main_memory, 0, binary_file_details->memory_main.size);
//     if (uc_mem_write(uc, binary_file_details->memory_main.address, tmp_main_memory, binary_file_details->memory_main.size))
//     {
//         fprintf(stderr, "Failed to clean main memory, quit!\n");
//         my_exit(-1);
//     }

//     //reset other memory
//     for (int i=0;i< binary_file_details->memory_other_count;i++)
//     {
//         char* tmp_other_memory=MY_STACK_ALLOC(binary_file_details->memory_other[i].size);
//         memset(tmp_other_memory, 0, binary_file_details->memory_other[i].size);
//         if (uc_mem_write(uc, binary_file_details->memory_other[i].address, tmp_other_memory, binary_file_details->memory_other[i].size))
//         {
//             fprintf(stderr, "Failed to clean other memory[%i], quit!\n",i);
//             my_exit(-1);
//         }
//     }
// }
void uc_unmap_all_memory(uc_engine *uc,current_run_state_t* current_run_state)
{
    #ifdef DEBUG
        printf_debug("uc_unmap_all_memory\n");
    #endif

    // printf_verbose("uc_mem_unmap. 0x%lx\n",binary_file_details->memory_main.address);
    // printf_verbose("uc_mem_unmap. 0x%lx\n",binary_file_details->stack.address);

    uc_mem_unmap(uc,binary_file_details->memory_main.address, binary_file_details->memory_main.size);
    uc_mem_unmap(uc,binary_file_details->stack.address, binary_file_details->stack.size);
    for (uint64_t i=0;i<binary_file_details->memory_other_count;i++)
    {
        // printf_verbose("uc_mem_unmap. 0x%lx\n",binary_file_details->memory_other[i].address);
        uc_mem_unmap(uc,binary_file_details->memory_other[i].address, binary_file_details->memory_other[i].size);
    }
}

uc_err my_uc_close(uc_engine *uc,current_run_state_t* current_run_state,char* desc)
{
    
    #ifdef DEBUG
        printf_debug("my_uc_close: %s\n",desc);
    #endif

    //uc_unmap_all_memory(uc,current_run_state); //DEBUGDEBUG - I think uc_close fixes this anyway
    uc_delete_all_hooks(uc, current_run_state);
    uc_err err = uc_close(uc); 
    // printf_verbose("CLOSE CLOSE: %s, %p\n",desc,uc);
    // printf_verbose("----------------\n");
    if (err != UC_ERR_OK)
    {
        fprintf(stderr, "Failed to close the uc_engine: %s\n", uc_strerror(err));
        my_exit(-1);
    }
    return err;
}
