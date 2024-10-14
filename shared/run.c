#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include "unicorn_engine.h"
#include "utils.h"
#include "unicorn_consts.h"
#include "structs.h"
#include "fileio.h"
#include "thread_management.h"
#include "configuration.h"
#include "math.h"


void run_the_actual_fault(const char *code_buffer,const size_t code_buffer_size,workload_t workload,current_run_state_t *current_run_state);


void print_run_info(current_run_state_t * current_run_state)
{
    FILE* f=current_run_state->file_fprintf;
    fprintf_output(f,"Filename              : %s\n",binary_file_details->binary_filename);
    fprintf_output(f,"Stack Start Address   : 0x%016llx\n",binary_file_details->stack_start_address);
    fprintf_output(f,"Stack Address         : 0x%016llx\n",binary_file_details->stack.address);
    fprintf_output(f,"Stack Size            : 0x%016llx\n",binary_file_details->stack.size);
    fprintf_output(f,"Code Start Address    : 0x%016llx\n",binary_file_details->code_start_address);
    fprintf_output(f,"Code End Address      : 0x%016llx\n",binary_file_details->code_end_address);
    fprintf_output(f,"Code Offset           : 0x%016llx\n",binary_file_details->code_offset);
    fprintf_output(f,"Fault Start Address   : 0x%016llx\n",binary_file_details->fault_start_address);
    fprintf_output(f,"Fault End Address     : 0x%016llx\n",binary_file_details->fault_end_address);
    fprintf_output(f,"Memory Address        : 0x%016llx\n",binary_file_details->memory_main.address);
    fprintf_output(f,"Memory Size           : 0x%016llx\n",binary_file_details->memory_main.size);

    for (uint64_t i=0;i<binary_file_details->memory_other_count;i++)
    {
        fprintf_output(f,"Other Memory Address  : 0x%016llx\n",binary_file_details->memory_other[i].address);
        fprintf_output(f,"Other Memory Size     : 0x%016llx\n",binary_file_details->memory_other[i].size);
    }
    for (uint64_t i=0;i<binary_file_details->hard_stops_count;i++)
    {
        fprintf_output(f,"Hard stop             : 0x%016llx\n",binary_file_details->hard_stops[i].address);
    }
}
// Function to count the number of lines in the file
int count_lines(FILE *fp) 
{
    int count = 0;
    char line[MAX_LINE_LENGTH_DISSASSEMBLE_FILE];

    while (fgets(line, sizeof(line), fp)) 
    {
        count++;
    }

    // Reset file pointer to the beginning of the file
    fseek(fp, 0, SEEK_SET);

    return count;
}
// Function to parse a line and extract the address, opcode mnemonic, and the rest of the line
void parse_disassembly_file_line(const char *line, unsigned int *address, char *op_mnemonic, char *rest_of_line) 
{
    sscanf(line, "%x: %s %[^\n]", address, op_mnemonic, rest_of_line);
    convertToUppercase(op_mnemonic);
    convertToUppercase(rest_of_line);
}


void print_stats(current_run_state_t *current_run_state)
{
    #ifdef DEBUG
        printf_debug("print_stats\n");
    #endif

    uint64_t register_count[MAX_REGISTERS]={0};
    //build the register counts
    for (uint64_t instr=1; instr < current_run_state->total_instruction_count+1; instr++)
    {
        for (int r=0; r < MAX_REGISTERS; r++)
        {
            if (is_bit_set(current_run_state->line_details_array[instr].the_registers_used, r))
            {
                register_count[r]++;
            }
        }
    }

    printf("\n~~~~~~~~~~~~~~~~~~ Print Stats  ~~~~~~~~~~~~~~~~~~~~~~\n");
    printf_output("Binary file under test:      %s\n",binary_file_details->binary_filename);

    // PRINT set memory INPUTS
    for (uint64_t i=0; i < binary_file_details->set_memory_count;i++)
    {
        if (binary_file_details->set_memory[i].length>0)
        {
            if (binary_file_details->set_memory[i].format == hex_format)
            {
                printf_output("Input %llu at address: 0x%" PRIx64 " provided:  ",i,binary_file_details->set_memory[i].address);
                phex(stdout,binary_file_details->set_memory[i].byte_array, binary_file_details->set_memory[i].length);
            }
        }
    }

    // PRINT new register INPUTS
    for (uint64_t i=0; i < binary_file_details->set_registers_count;i++)
    {
        printf_output("Register: %s. Register Value: 0x%" PRIx64 ".\n",register_name_from_int(binary_file_details->set_registers[i].reg), binary_file_details->set_registers[i].reg_value);
    }
    printf("\n");
    printf_output("Start faults at address:     0x%08llx\n", binary_file_details->fault_start_address);
    printf_output("End faults at address:       0x%08llx\n\n", binary_file_details->fault_end_address);
    printf_output("Printing usage of registers: \n");

    //print the register info
    for (int r=0; r < MAX_REGISTERS; r++) 
    {
        if (register_count[r]>0)
        {
            printf("\t(%s):\t%8lli   \t\t \n",register_name_from_int(r),register_count[r]);
        }
    }
}

float ease_out(float x)
{
    return 1- pow(1-x,EASE_OUT_POWER);
}

uint64_t get_next_checkpoint_number(uint64_t count,uint64_t num_checkpoints,uint64_t num_instructions,uint64_t fault_instruction_min)
{
    if (num_checkpoints >=num_instructions)
    {
        // If we're asking for more checkpoints than there are instructions - just return the number of instructions!
        return count+fault_instruction_min-1;
    }
        float percent=((float)count/(float)(num_checkpoints+1));
        float line_float_percent=ease_out(percent);
        uint64_t line_actual=(line_float_percent * num_instructions)+fault_instruction_min-1;

        /* TEMPTEMP*/
        // printf("\nGetting next checkpoint\n");
        // printf("Count:                    %li\n" ,count);
        // printf("num_checkpoints           %li\n" ,num_checkpoints);
        // printf("instructions              %li\n" ,num_instructions);
        // printf("percent                   %f\n"  ,percent);
        // printf("line_float_percent        %f\n"  ,line_float_percent);
        // printf("line_actual               %li\n" ,line_actual);
        // printf("fault_instruction_min     %li\n" ,fault_instruction_min);
        // printf("About to return          %li\n" ,line_actual + fault_instruction_min -1 );
        /* TEMPTEMP */

        return line_actual;
}


void run_to_count_total_instructions(current_run_state_t* current_run_state)
{
    uc_engine *uc_count;
    my_uc_engine_setup(&uc_count,current_run_state,"uc_count");

    printf("\n~~~~ Running the program once to count the instructions ~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
    current_run_state->run_mode=eCOUNT_INSTRUCTIONS_rm;
    current_run_state->run_state=NONE_rs;
    current_run_state->timeit=true; 
    current_run_state->address_hit_counter=my_malloc(sizeof(address_hit_counter_t),"Address hit counter");
    current_run_state->address_hit_counter->min_address=0xFFFFFFFFFFFFFFFF;
    current_run_state->address_hit_counter->mod_address=0xFFFFFFFFFFFFFFFF;
    current_run_state->address_hit_counter->max_address=0;

    uc_hook hk_min_max_mod;
    my_uc_hook_add("hk_min_max_mod",uc_count, &hk_min_max_mod, UC_HOOK_CODE, hook_min_max_mod, current_run_state,1,0);
    //HACKHACK for some reason without this it doesn't count the instructions correctly.!?!?!?
    
    //my_uc_hook_add("placebo",uc, &hk_placebo, UC_HOOK_CODE, hook_placebo, current_run_state,1,0);
    my_uc_engine_start(uc_count, current_run_state,0);
    //my_uc_hook_del("hk_placebo",uc, hk_placebo,current_run_state);

    my_uc_hook_del("hk_min_max_mod",uc_count, hk_min_max_mod,current_run_state);

    current_run_state->total_instruction_count=current_run_state->instruction_count;
    current_run_state->fault_instruction_min=1;
    current_run_state->fault_instruction_max=current_run_state->instruction_count;
    uint64_t max=current_run_state->address_hit_counter->max_address;
    uint64_t min=current_run_state->address_hit_counter->min_address;
    uint64_t mod=current_run_state->address_hit_counter->mod_address;
    uint64_t size_to_malloc=sizeof(uint64_t)*(((max-min)/mod)+1);

    current_run_state->address_hit_counter->counter=my_malloc(size_to_malloc,"hit counter array");
    memset(current_run_state->address_hit_counter->counter,0,size_to_malloc);

    uint64_t num_instr=current_run_state->total_instruction_count;
    uint64_t tpi=0;
    if (num_instr != 0)
    {
        tpi=current_run_state->time_to_run/num_instr;
    }
        
    printf_output("Total instructions run:   %llu\n",num_instr);    
    printf_output("Time to run:              %llu ns \n", current_run_state->time_to_run);
    printf_output("Time per instruction:     %llu ns \n", tpi);
    my_uc_close(uc_count,current_run_state,"uc_count");

}

void print_checkpoints(current_run_state_t *current_run_state)
{
    // Used for debuging DEBUGDEBUG
    for (uint64_t i=1;i < current_run_state->total_instruction_count;i++)
    {
        if (current_run_state->line_details_array[i].checkpoint == true)
        {
            printf ("Checkpoint %llu address: 0x%llx\n", i, current_run_state->line_details_array[i].address);
        }
    }
}

void run_to_write_stats(current_run_state_t *current_run_state)
{
    // this is needed for the hitcounters 
    //run_to_count_total_instructions(current_run_state);          
    

    #ifdef DEBUG
        printf_debug("run_to_write_stats\n");
    #endif
    FILE *fd=current_run_state->file_fprintf;
    printf("\n~~~~ Running to store all the instructions~~~~~~~~~~\n");

    uint64_t total_instrs=current_run_state->total_instruction_count;
    if (total_instrs == 0)
    {
        fprintf (stderr, "Total number of instructions is 0.\n");
        my_exit(-1);
    }

    // There's no point in building checkpoints outside of the instructions that we're going to fault (yes - except the first one maybe!)
    uint64_t total_faultrange_instrs=current_run_state->fault_instruction_max - current_run_state->fault_instruction_min+1;
    if (total_faultrange_instrs == 0)
    {
        fprintf (stderr, "Range of faulted instructions is 0.\n");
        my_exit(-1);
    }


    
    if (current_run_state->fault_instruction_max  > total_instrs )
    {
        fprintf (stderr, "Fault Instruction Max is bigger than the total number of instructions.\n");
        my_exit(-1);
    }

    // Create the space for every line's stats.
    // +1 because we don't start at zero. Urgh. 0 is reserved for not-a-line rather than the first line. Got it? 
    current_run_state->line_details_array=my_malloc((total_instrs+2) * sizeof(line_details_t), "line_details_array");

    uint64_t next_checkpoint_count=1;
    uint64_t valid_checkpoint_count=0;
    uint64_t first_checkpoint_instruction=0;
    uint64_t next_checkpoint_instruction=0;
    uint64_t previous_checkpoint_instruction=0;

    if (current_run_state->start_from_checkpoint == 1)
    {
        if (current_run_state->total_num_checkpoints < 1)
        {
            fprintf (stderr, "'Number of Checkpoints' is not valid.\n");
            my_exit(-1);
        }

        // Add up the size of all the memory: stack, main_memory, other memory
        uint128_t size_for_one=binary_file_details->stack.size + binary_file_details->memory_main.size;
        for (int i=0;i<binary_file_details->memory_other_count;i++)
        {
            size_for_one=size_for_one + binary_file_details->memory_other[i].size;
        }

        // multiply the memory size by the number of checkpoints.
        uint128_t big_number= current_run_state->total_num_checkpoints * size_for_one;
        big_number +=(total_instrs +1)* sizeof (line_details_t);

        // Let the user know how much space they're about to use up if they're using checkpoints 
        fprintf(fd, " >> Total memory needed: %s.\n", human_size(big_number));
        fprintf(fd, " >> If this fails - consider setting 'number of checkpoints' to a lower number than: %llu.\n",current_run_state->total_num_checkpoints); 
    
        first_checkpoint_instruction=get_next_checkpoint_number(1,current_run_state->total_num_checkpoints,total_faultrange_instrs,current_run_state->fault_instruction_min);
        next_checkpoint_instruction=first_checkpoint_instruction;
        previous_checkpoint_instruction=first_checkpoint_instruction;
    }

    for (uint64_t i=1; i < total_instrs+1; i++)
    {
        // set to blank values for every line 
        current_run_state->line_details_array[i].the_registers_used=0;
        current_run_state->line_details_array[i].address=0;
        current_run_state->line_details_array[i].hit_count=0;
        current_run_state->line_details_array[i].size=0;
        current_run_state->line_details_array[i].nearest_checkpoint=NO_CHECKPOINT;
        current_run_state->line_details_array[i].checkpoint=false;

        if (current_run_state->start_from_checkpoint == 1)
        { 
            if (valid_checkpoint_count<current_run_state->total_num_checkpoints)
            {

                if (i >=first_checkpoint_instruction)
                {

                    // Don't do anything until we reach the first checkpoint
                    if (i == next_checkpoint_instruction)
                    { 
                        // This instruction is a checkpoint
                        current_run_state->line_details_array[i].nearest_checkpoint=i;
                        current_run_state->line_details_array[i].checkpoint=true;  // this is a checkpoint

                        while (i == next_checkpoint_instruction)
                        {
                            // towards the end the numbers get very small - so will round up to the same linenumber - keep incrementing until you get another instruction
                            // Yes - this will reduce the number of checkpoints - but not too much.
                            next_checkpoint_count++;
                            previous_checkpoint_instruction=next_checkpoint_instruction;
                            next_checkpoint_instruction=get_next_checkpoint_number(next_checkpoint_count,current_run_state->total_num_checkpoints,total_faultrange_instrs,current_run_state->fault_instruction_min);
                        }
                        valid_checkpoint_count++;
                    }
                    else
                    {
                        // Not a check point
                        current_run_state->line_details_array[i].nearest_checkpoint=previous_checkpoint_instruction;
                    }
                }
            }
            else
            {
                // no more check points
                current_run_state->line_details_array[i].nearest_checkpoint=previous_checkpoint_instruction;
            }
        }
    }
    printf_output("Total number of checkpoints created: %llu (requested: %llu). \n",valid_checkpoint_count,current_run_state->total_num_checkpoints); 
    current_run_state->total_num_checkpoints=valid_checkpoint_count;

    uc_engine *uc_stats;
    my_uc_engine_setup(&uc_stats,current_run_state,"uc_stats");


    // Add hook
    uc_hook hk_stats;
    my_uc_hook_add("hk_stats",uc_stats, &hk_stats, UC_HOOK_CODE, hook_code_stats, current_run_state, 1,0);
    // go
    my_uc_engine_start(uc_stats, current_run_state,0);
    // Delete hook
    my_uc_hook_del("hk_stats",uc_stats, hk_stats, current_run_state);
    print_stats(current_run_state);
    print_checkpoints(current_run_state);
  //  my_uc_close(uc_stats,current_run_state,"uc_stats"); // ARGHHGHGHGHHGHGH - something gets double free'd in here.
}


void restore_from_checkpoint_timeit(current_run_state_t *current_run_state)
{
    #ifdef DEBUG
        printf_debug("restore_from_checkpoint_timeit\n");
    #endif

    current_run_state->run_mode=eTIMING_CHECKPOINT_rm;
    printf("\n~~~~ Running again to time restoring from a checkpoint ~~~~~~~~~~\n");
    uc_engine* uc_timingtest;
    my_uc_engine_setup(&uc_timingtest, current_run_state,"uc_timingtest");

    /** For printing each line  - ADD the hook*/
    uc_hook hk_placebo; //HACKHACK

    //Run the program
    my_uc_hook_add("hk_placebo",uc_timingtest, &hk_placebo, UC_HOOK_CODE, hook_placebo, current_run_state,1,0); //HACKHACK

    //Run the program

    current_run_state->timeit=true; //CHECKCHECK
    my_uc_engine_start(uc_timingtest, current_run_state,0);


    my_uc_hook_del("hk_placebo",uc_timingtest,hk_placebo,current_run_state); //HACKHACK
    my_uc_close(uc_timingtest,current_run_state,"uc_timingtest");

}

void goldenrun_full_it (current_run_state_t* current_run_state)
{
    // this is needed for the hitcounters 
    run_to_count_total_instructions(current_run_state);  
    printf("\n~~~~ GRF Running the program to display all instructions ~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
    uc_engine *uc_golden_full;
    my_uc_engine_setup(&uc_golden_full,current_run_state,"uc_golden_full");
    current_run_state_reset(current_run_state); 
    current_run_state->run_mode=eGOLDENRUN_FULL_rm;
    /** For printing each line  - ADD the hook*/
    uc_hook hk_code_print_instructions; 
    my_uc_hook_add("hk_code_print_instructions",uc_golden_full, &hk_code_print_instructions, UC_HOOK_CODE, hook_code_print_instructions, current_run_state,1,0);
    my_uc_engine_start(uc_golden_full, current_run_state,0);     /** time one run **/
    /** For printing each line  - DELETE the hook*/
    my_uc_hook_del("hk_code_print_instructions",uc_golden_full, hk_code_print_instructions,current_run_state);


    printf_output("Total instructions in faulting range:   %llu\n",current_run_state->instruction_count);    
    print_outputs(uc_golden_full, current_run_state);
    my_uc_close(uc_golden_full,current_run_state,"uc_golden_full");
}





void goldenrun_it(current_run_state_t* current_run_state)
{

    printf("\n~~~~ Running the program to display all instructions in faulting range ~~~~~~~~~~~~~~~~~~~~~~~~\n");
    uc_engine *uc_golden;
    my_uc_engine_setup(&uc_golden,current_run_state,"uc_golden");

    current_run_state_reset(current_run_state); // reset the counter etc.
    current_run_state->run_mode=eGOLDEN_rm;
    /** For printing each line in the faulting range - ADD the hook */
    uc_hook hk_code_print_fault_instructions;
    my_uc_hook_add("hk_code_print_fault_instructions",uc_golden, &hk_code_print_fault_instructions, UC_HOOK_CODE, hook_code_print_fault_instructions, current_run_state,1,0);

    my_uc_engine_start(uc_golden, current_run_state,0);  

    /** For printing each line in the faulting range - DELETE the hook */
    my_uc_hook_del("hk_code_print_fault_instructions",uc_golden, hk_code_print_fault_instructions,current_run_state);
    printf_output("Total instructions in faulting range:   %llu\n",current_run_state->instruction_count);    

    print_outputs(uc_golden, current_run_state);
    my_uc_close(uc_golden, current_run_state, "uc_golden");

}


void memhook_it(current_run_state_t* current_run_state)
{
    uc_engine* uc_mem;
    my_uc_engine_setup(&uc_mem,current_run_state,"uc_mem");

    current_run_state_reset(current_run_state); // reset the counter etc.

    
    //Print every line that runs
    uc_hook hk_code_print_instructions, hk_mem_valid;
    my_uc_hook_add("hk_code_print_instructions",uc_mem, &hk_code_print_instructions, UC_HOOK_CODE, hook_code_print_instructions, current_run_state,1,0);
    /* ADD two memory hooks */
    my_uc_hook_add("hk_mem_valid",uc_mem, &hk_mem_valid, UC_HOOK_MEM_WRITE, hook_mem_write, current_run_state,1,0);
    my_uc_hook_add("hk_mem_valid",uc_mem, &hk_mem_valid, UC_HOOK_MEM_READ_AFTER, hook_mem_read_after, current_run_state,1,0);

    my_uc_engine_start(uc_mem, current_run_state,0);

    my_uc_hook_del("hk_code_print_instructions",uc_mem, hk_code_print_instructions,current_run_state);
    my_uc_hook_del("hk_mem_valid",uc_mem, hk_mem_valid,current_run_state);
    print_outputs(uc_mem, current_run_state);
    my_uc_close(uc_mem,current_run_state,"uc_mem");
}

void *fault_it_thread(void *user_data)
{
    context_and_thread_num_t* send_to_thread=(context_and_thread_num_t*)user_data;
    consume_context_t* context=send_to_thread->context;
    workload_t workload;
    current_run_state_t current_run_state={0};
    current_run_state_init(&current_run_state);
    current_run_state.run_mode=eFAULT_rm;
    
    current_run_state.line_details_array=context->line_details_array;
    current_run_state.start_from_checkpoint=context->start_from_checkpoint;
    current_run_state.stop_on_equivalence=context->stop_on_equivalence;
    current_run_state.total_num_checkpoints=context->total_num_checkpoints;
    current_run_state.total_instruction_count=context->total_instrs;
    current_run_state.timeit=context->timeit;
    current_run_state.max_instructions=context->max_instructions;
    current_run_state.display_disassembly=context->display_disassembly;
    current_run_state.directory=context->directory;
    if (strcmp(context->directory, "stdout") != 0)
    {
        char pfile[96];
        sprintf(pfile, "%s/%04i.txt", context->directory,send_to_thread->thread_num);
        if ((current_run_state.file_fprintf=fopen(pfile, "w")) == NULL)
        {
            fprintf(stderr, "Error opening file descriptor for thread: %s\n", pfile);
            my_exit(-1);
        }
    }
    else
    {
        current_run_state.file_fprintf=stdout;
    }

    do
    {
        // LOCK
        pthread_mutex_lock(&context->consume_data_lock);
        memset(&workload, 0, sizeof(workload_t));

        if (context->current_instruction_range_fault != NULL)
        {
            workload.instruction=context->instruction;
            workload.instruction_range_fault=context->current_instruction_range_fault;
            move_to_next(context);
        }
        pthread_mutex_unlock(&context->consume_data_lock);
        // UNLOCK
        if (workload.instruction > context->total_instrs )
        {
                fprintf(stderr, "Instruction to fault: %llu is larger than the total number of instructions: %llu !\n",
                    workload.instruction,
                    context->total_instrs );
                my_exit(-1);
        }
        if (workload.instruction_range_fault != NULL)
        {
            run_the_actual_fault(context->code_buffer, context->code_buffer_size, workload, &current_run_state);
        }
    } while (workload.instruction_range_fault != NULL);

    pthread_exit(NULL);

}


void free_checkpoint_details(current_run_state_t* current_run_state)
{
    for (uint64_t i=1;i<current_run_state->total_instruction_count;i++)
    {
        if (current_run_state->line_details_array[i].checkpoint == true)
        {
            my_free(current_run_state->line_details_array[i].memory_main,"line_details_array - memory main");
            // my_free(current_run_state->line_details_array[i].stack,"line_details_array - stack");
            for (uint64_t j=0;j<binary_file_details->memory_other_count;j++)
            {
                //my_free(current_run_state->line_details_array[i].memory_other[j],"line_details_array - memory other");
            }
          //  my_free(current_run_state->line_details_array[i].memory_other,"line_details_array - memory other pointer");
        }
    }
}

void stats_it(current_run_state_t* current_run_state)
{
    // Run 1
    run_to_count_total_instructions(current_run_state);  
    uint64_t time_run=current_run_state->time_to_run;  // Keep the timing from the run only counting instructions.
    
    // Run 2
    current_run_state_reset(current_run_state); // reset the counter etc.
    current_run_state->total_num_checkpoints=4;
    current_run_state->start_from_checkpoint=true;
    run_to_write_stats(current_run_state);

    // 3rd run
    current_run_state_reset(current_run_state); // reset the counter etc.
    restore_from_checkpoint_timeit(current_run_state);

    uint64_t time_checkpoint=current_run_state->time_to_restore_checkpoint;
    uint64_t num_instr=current_run_state->total_instruction_count;

    printf_output("Time of first run:                             %llu ns \n", time_run);
    printf_output("Time to restore checkpoint:                    %llu ns \n", time_checkpoint);
    printf_output("Time per instruction (approx):                 %llu ns \n", time_run/num_instr);
    printf_output("Equivalent instructions to restore checkpoint: %llu\n", time_checkpoint/(time_run/num_instr));
    free_checkpoint_details(current_run_state);
}


void debug_it(current_run_state_t* current_run_state)
{
    printf("\n********************************************************************************************************\n");
    printf("                        DEBUG");
    printf("\n********************************************************************************************************\n");
     // this is needed for the hitcounters 
    run_to_count_total_instructions(current_run_state);  
    uc_engine *uc_debug;
    my_uc_engine_setup(&uc_debug,current_run_state,"uc_debug");
    current_run_state->run_mode=eDEBUG_rm;

    current_run_state_reset(current_run_state); 
    uc_hook hk_code_print_debug; 
    my_uc_hook_add("hk_code_print_debug",uc_debug, &hk_code_print_debug, UC_HOOK_CODE, hook_code_print_debug, current_run_state,1,0);
    my_uc_engine_start(uc_debug, current_run_state,0);     /** time one run **/
    /** For printing each line  - DELETE the hook*/
    my_uc_hook_del("hk_code_print_debug",uc_debug, hk_code_print_debug,current_run_state);


    printf_output("Total instructions in faulting range:   %llu\n",current_run_state->instruction_count);    
    print_outputs(uc_debug, current_run_state);
    my_uc_close(uc_debug,current_run_state,"uc_debug");
}


void fault_it(current_run_state_t* current_run_state,run_list_t* run_list, uint64_t num_threads)
{
    int timeit=current_run_state->timeit;

    // Run 1 - count instructions
    run_to_count_total_instructions(current_run_state);  

    uint64_t min=current_run_state->total_instruction_count;
    uint64_t max=1;

    // We're checking the fault range from the fault rules list - there's no point in creating
    // checkpoints for instructions that aren't going to be faulted.
    instruction_range_fault_t* instr=run_list->instruction_range_fault;
    while (instr != NULL)
    {
        if (instr->instruction_start < min)
            min=instr->instruction_start ;
        if (instr->instruction_end > max)
            max=instr->instruction_end ;
        instr=instr->next;
    }
    current_run_state->fault_instruction_min=min;
    current_run_state->fault_instruction_max=max;
    uint64_t diff=max-min+1;
    if (current_run_state->total_num_checkpoints > diff)
    {
        current_run_state->total_num_checkpoints=diff;
    }

    // Run 2 - write the stats         
    current_run_state_reset(current_run_state); // reset the counter etc.
    current_run_state->run_mode=eSTATS_rm;
    run_to_write_stats(current_run_state);

    // Initialise consumer context
    consume_context_t context;
    current_run_state->timeit=timeit;
    initialise_consume_context(&context,run_list->instruction_range_fault,current_run_state);

    context.directory=current_run_state->directory;
    if (strcmp(context.directory, "stdout") != 0)
    {
        DIR *dir;
        dir=opendir(context.directory);
        if (!dir)
        {
	    if  (ENOENT == errno) // directory does not exist
	    {
	        if (mkdir(context.directory, 0777) == -1)
                {
                   fprintf(stderr, "Error creating directory: %s\n", context.directory);
                   my_exit(-1);
                }
	    }
	    else
	    {
                fprintf(stderr, "Error opening directory: %s\n", context.directory);
		perror("opendir");
                my_exit(-1);
	    }
		
        }
    }

    fprintf(stdout, "Directory for results: %s\n", context.directory);
    context_and_thread_num_t send_to_thread[num_threads];
    pthread_t *thread_ids=MY_STACK_ALLOC(sizeof(pthread_t) * num_threads );
    
    for (int i=0; i < num_threads; i++)
    {
        fprintf(stdout, "Thread %i created.\n", i);
        send_to_thread[i].context=&context;
        send_to_thread[i].thread_num=i;
        pthread_create(&thread_ids[i], NULL, fault_it_thread, &send_to_thread[i]);
    }

    for (int i=0; i < num_threads; i++)
    {
        pthread_join(thread_ids[i], NULL);
        fprintf(stdout, "\nThread %i rejoined.", i);
    }
    printf ("\n");
   // free_checkpoint_details(current_run_state);

}

uint64_t count_faults_for_instruction_range(instruction_range_fault_t *current_instruction_range_fault)
{  
    // This is used to work out the maximum equivalance size - likely to be around 1666 - not that large!
    uint64_t count_running_total=0;
        
    target_fault_t *current_fault=current_instruction_range_fault->target_fault_head;

    while (current_fault != NULL)
    {
        uint64_t count_targets=0;

        if (current_fault->target == reg_ft)
        {
            // FLAG
            for (int target_num=0; target_num < MAX_REGISTERS; target_num++)
            {
                if (is_bit_set(current_fault->register_bit, target_num))
                {
                    count_targets++;
                }
            }
        }
        else if(current_fault->target == instruction_pointer_ft)
        {
            count_targets++;
        }
        else if(current_fault->target == instruction_ft)
        {
            count_targets++;
        }
        else 
        {
            fprintf(stderr,"No valid target found for fault at line: %llu.\n",current_instruction_range_fault->instruction_start);
            my_exit(-1);
        }

        //OP CODE FILTER
        opcode_filter_fault_t *current_opcode_filter_fault=current_fault->opcode_filter_fault_head;
        while (current_opcode_filter_fault != NULL)
        {
            lifespan_fault_t *current_lifespan_fault_list=current_opcode_filter_fault->lifespan_head;
            while (current_lifespan_fault_list != NULL)
            {
                operation_fault_t *current_operation_fault=current_lifespan_fault_list->operation_fault_head;
                while (current_operation_fault != NULL)
                {
                    if (current_operation_fault->mask_count == 0)
                    {
                        //if mask_count is zero then it'll be a Instruction Pointer that doesn't use a mask.
                        count_running_total+=count_targets;
                    }
                    else
                    {
                        count_running_total +=current_operation_fault->mask_count * count_targets;
                    }
                    current_operation_fault=current_operation_fault->next;
                }
                current_lifespan_fault_list=current_lifespan_fault_list->next;
            }
            current_opcode_filter_fault=current_opcode_filter_fault->next;
        }
        current_fault=current_fault->next;

    }
    return count_running_total;
}

void get_on_with_it(const char *code_buffer, const size_t code_buffer_size, current_run_state_t* current_run_state)
{
    FILE* f=current_run_state->file_fprintf;
    uint64_t fault_address=current_run_state->line_details_array[current_run_state->fault_rule.instruction].address;
    uint64_t hit_count=current_run_state->line_details_array[current_run_state->fault_rule.instruction].hit_count;

    fault_address=thumb_check_address(fault_address);
    // DO NOT TOUCH THIS FORMAT!! It is used by ff-builddatabase.py to put the data into the database
    fprintf(f, "\n\n\n\n##### Starting new run. ");
    fprintf(f, "Address: 0x%" PRIx64 ". Hit: %llu. Lifespan: %llu. ",fault_address,hit_count,current_run_state->fault_rule.lifespan.count);
    print_fault_rule_no_newline(f,&current_run_state->fault_rule);
    fprintf(f, " ###\n");


    uc_engine* uc; 
    my_uc_engine_setup(&uc,current_run_state,"get_on_with_it");


    current_run_state_reset(current_run_state); // reset the counter etc.
    current_run_state->fault_rule.set=true;
    //Run the program
    uc_hook hk_placebo;

    my_uc_hook_add("hk_placebo",uc, &hk_placebo, UC_HOOK_CODE, hook_placebo, current_run_state,1,0);
    my_uc_engine_start(uc, current_run_state, current_run_state->max_instructions); 
    my_uc_hook_del("hk_placebo",uc, hk_placebo,current_run_state);

    switch (current_run_state->run_state)
    {
        case END_ADDRESS_AND_FAULTED_rs:
            fprintf_output(f,"Run result: reached end address after faulting.\n");
            print_outputs(uc, current_run_state);
            break;
        case FAULTED_rs:
            fprintf_output(f,"Run result: faulted but did not reach end address.\n");
            print_outputs(uc, current_run_state);
            break;
        case HARD_STOP_rs:
            fprintf_output(f,"Run result: reached a 'hard stop' address.\n");
            print_outputs(uc, current_run_state);
            break;
        case ERRORED_rs:
            fprintf_output(f,"Run result: fault errored program - last instruction %llu.\n", current_run_state->instruction_count);
            print_outputs(uc, current_run_state);
            break;
        case TIMED_OUT_rs:
            fprintf_output(f,"Run result: timed out - exiting.\n");
            print_outputs(uc, current_run_state);
            break;
        case EQUIVALENT_rs:
            fprintf_output(f,"Run result: run ended early - equivalence found.\n");
            break;
        case INTERRUPT_rs:
            fprintf_output(f,"Run result: run ended early - system interrupt occurred.\n");
            break;
        case END_ADDRESS_rs:
            fprintf_output(f,"Run result: reached end address no fault occurred. Perhaps the registers to fault are not touched in those instructions (or the opcode).\n");
            break;
        case MAX_INSTRUCTIONS_REACHED_rs:
            fprintf_output(f,"Run result: max instructions reached- exiting.\n");
            print_outputs(uc, current_run_state);
            break;
        case NONE_rs:
            fprintf_output(f,"Run result: none.\n");
            break;

        default:
            fprintf_output(f,"Run result: no result code... That shoudn't happen....?! Value is: %i.\n", current_run_state->run_state);
    }
    if (current_run_state->time_to_run != 0)
    {
        fprintf_output(f,"Instruction: %llu. Checkpoint %llu Time to run: %llu ns\n ", 
            current_run_state->fault_rule.instruction,
            current_run_state->line_details_array[current_run_state->fault_rule.instruction].nearest_checkpoint, 
            current_run_state->time_to_run);

        fprintf(f, "%llu,%llu,%llu,%s,PLOTTINGLINE (for python graphs).\n ", 
            current_run_state->fault_rule.instruction,
            current_run_state->line_details_array[current_run_state->fault_rule.instruction].nearest_checkpoint, 
            current_run_state->time_to_run,
            run_state_to_string(current_run_state->run_state));
    }
    my_uc_close(uc,current_run_state,"get_on_with_it");  
}

void run_the_actual_fault( const char *code_buffer,const size_t code_buffer_size,
                            workload_t workload,current_run_state_t *current_run_state)
{

    instruction_range_fault_t *current_instruction_range_fault=workload.instruction_range_fault;
    current_run_state->equivalence_count=0;
    
    if (current_instruction_range_fault != NULL)
    {
        if ((workload.instruction % DISPLAY_EVERY) == 0)
        {
            fprintf(stdout,".%llu.",workload.instruction);
            fflush(stdout);
        }
        current_run_state->fault_rule.set=true;
        current_run_state->fault_rule.instruction=workload.instruction;
        current_run_state->fault_rule.lifespan.count=0;
        current_run_state->fault_rule.lifespan.live_counter=0;
        current_run_state->fault_rule.lifespan.original_target_value=0;
        current_run_state->fault_rule.lifespan.original_instruction_value_size=0;
        memset(current_run_state->fault_rule.lifespan.original_instruction_value,0,MAX_INSTRUCTION_BUFFER_REPLACEMENT_SIZE);

        target_fault_t *current_fault=current_instruction_range_fault->target_fault_head;
        while (current_fault != NULL)
        {
            current_run_state->fault_rule.target=current_fault->target;
            switch (current_run_state->fault_rule.target)
            {
                case instruction_pointer_ft:
                    {
                        // LOOPING THROUGH THE OPCODE FILTERS
                        opcode_filter_fault_t *current_opcode_filter_fault=current_fault->opcode_filter_fault_head;
                        while (current_opcode_filter_fault != NULL)
                        {
                            if  (current_opcode_filter_fault->string == NULL || 
                                        (strstr(current_run_state->line_details_array[workload.instruction].op_mnemonic,current_opcode_filter_fault->string) != NULL)
                                        )
                            {
                                lifespan_fault_t *current_lifespan_fault=current_opcode_filter_fault->lifespan_head;
                                while (current_lifespan_fault != NULL)
                                {
                                    operation_fault_t *current_operation_fault=current_lifespan_fault->operation_fault_head;
                                    // LOOPING THROUGH OPERATIONS
                                    while (current_operation_fault != NULL)
                                    {
                                        current_run_state->fault_rule.number=0; // Not relevant
                                        current_run_state->fault_rule.opcode_filter_fault=current_opcode_filter_fault->string;
                                        current_run_state->fault_rule.lifespan=current_lifespan_fault->lifespan;
                                        current_run_state->fault_rule.operation=current_operation_fault->operation;
                                        current_run_state->fault_rule.mask=0; // Not relevant
                                        get_on_with_it(code_buffer, code_buffer_size, current_run_state);

                                        current_operation_fault=current_operation_fault->next;
                                    }
                                    current_lifespan_fault=current_lifespan_fault->next;
                                }
                            }
                            current_opcode_filter_fault=current_opcode_filter_fault->next;
                        }
                        break;
                    }
                case reg_ft:
                    {
                        //LOOPING THROUGH REGISTERS            
                        for (int register_counter=0; register_counter < MAX_REGISTERS; register_counter++)
                        {
                            // The bit HAS to be set for the register(eg FAULT: register 7). 
                            // And then: either FORCE IT or - check that this register is used at this address.
                            if  (
                                    (is_bit_set(current_fault->register_bit, register_counter))  
                                    &&
                                        (current_fault->force == true   
                                        ||
                                        is_bit_set(current_run_state->line_details_array[workload.instruction].the_registers_used, register_counter))
                                )
                            {
                                // LOOPING THROUGH THE OPCODE FILTERS
                                opcode_filter_fault_t *current_opcode_filter_fault=current_fault->opcode_filter_fault_head;
                                while (current_opcode_filter_fault != NULL)
                                {
                                    if  (   (current_opcode_filter_fault->string == NULL)
                                            || 
                                            (strstr(current_run_state->line_details_array[workload.instruction].op_mnemonic,current_opcode_filter_fault->string) != NULL)
                                        )
                                    {
                                        lifespan_fault_t *current_lifespan_fault=current_opcode_filter_fault->lifespan_head;
                                        while (current_lifespan_fault != NULL)
                                        {
                                            operation_fault_t *current_operation_fault=current_lifespan_fault->operation_fault_head;
                                            // LOOPING THROUGH OPERATIONS
                                            while (current_operation_fault != NULL)
                                            {
                                                // LOOPING THROUGH MASKS
                                                for (uint64_t mask_counter=0; mask_counter < current_operation_fault->mask_count; mask_counter++)
                                                {
                                                    current_run_state->fault_rule.number=register_counter;
                                                    current_run_state->fault_rule.opcode_filter_fault=current_opcode_filter_fault->string;
                                                    current_run_state->fault_rule.lifespan=current_lifespan_fault->lifespan;
                                                    current_run_state->fault_rule.operation=current_operation_fault->operation;
                                                    current_run_state->fault_rule.mask=current_operation_fault->masks[mask_counter];
                                                    current_run_state->fault_rule.force=current_fault->force;
                                                    get_on_with_it(code_buffer, code_buffer_size, current_run_state);
                                                }
                                                current_operation_fault=current_operation_fault->next;
                                            }
                                            current_lifespan_fault=current_lifespan_fault->next;
                                        }
                                    }
                                current_opcode_filter_fault=current_opcode_filter_fault->next;
                                }
                            }
                        }
                        break;
                    }
                case instruction_ft:
                    {
                        // LOOPING THROUGH THE OPCODE FILTERS for code
                        opcode_filter_fault_t *current_opcode_filter_fault=current_fault->opcode_filter_fault_head;
                        while (current_opcode_filter_fault != NULL)
                        {
                            if  (   (current_opcode_filter_fault->string == NULL)
                                    || 
                                    (strstr(current_run_state->line_details_array[workload.instruction].op_mnemonic,current_opcode_filter_fault->string) != NULL)
                                )
                            {
                                lifespan_fault_t *current_lifespan_fault=current_opcode_filter_fault->lifespan_head;
                                while (current_lifespan_fault != NULL)
                                {
                                    operation_fault_t *current_operation_fault=current_lifespan_fault->operation_fault_head;
                                    // LOOPING THROUGH OPERATIONS
                                    while (current_operation_fault != NULL)
                                    {
                                        // LOOPING THROUGH MASKS
                                        for (uint64_t mask_counter=0; mask_counter < current_operation_fault->mask_count; mask_counter++)
                                        {
                                            current_run_state->fault_rule.number=0; //Not relevant
                                            current_run_state->fault_rule.opcode_filter_fault=current_opcode_filter_fault->string;
                                            current_run_state->fault_rule.lifespan=current_lifespan_fault->lifespan;
                                            current_run_state->fault_rule.operation=current_operation_fault->operation;
                                            current_run_state->fault_rule.mask=current_operation_fault->masks[mask_counter];
                                            get_on_with_it(code_buffer, code_buffer_size, current_run_state);
                                        }
                                        current_operation_fault=current_operation_fault->next;
                                    }
                                current_lifespan_fault=current_lifespan_fault->next;
                            }
                        current_opcode_filter_fault=current_opcode_filter_fault->next;
                        }
                        break;
                    }
            }
            }
            #ifdef DEBUGs
                printf_debug("Getting next fault instructions: %llu\n",i);
            #endif
            current_fault=current_fault->next;
        }
    }
    if (current_run_state->stop_on_equivalence)
    {
        // Show all the equivalents for this instruction numbber
        print_equivalence_list(current_run_state, workload.instruction);
        for (int64_t i=current_run_state->equivalence_count-1; i>=0; i--)
        {
            #ifdef DEBUGs
                printf_debug("Freeing equivalence lists: %llu\n",i);
            #endif
            // Free the hashes 
            my_free(current_run_state->equivalences[i].faults,"equivalences faults");
            my_free(current_run_state->equivalences[i].hashes,"equivalences hashes");
        }
        my_free(current_run_state->equivalences,"equivalences");
        current_run_state->equivalences=0;
    }

}
