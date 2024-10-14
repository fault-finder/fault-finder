#include <unicorn/unicorn.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>
#include <unistd.h>
#include "../shared/structs.h"
#include "../shared/run.h"
#include "../shared/utils.h"
#include "../shared/fileio.h"
#include "../shared/thread_management.h"
#include "../shared/configuration.h"
#include "../shared/unicorn_engine.h"

static void usage(char *this_binary_file)
{
    fprintf(stderr, "Usage %s json_run_file\n",this_binary_file);
    my_exit(-1);
}
void print_run_file_details(const run_details_t* run_details)
{
    printf ("\n~~~ Run details  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
    printf_output("json filename:          %s\n",run_details->json_filename);
    printf_output("run mode:               %s\n",run_mode_to_string(run_details->run_mode));
    if (run_details->run_mode == eFAULT_rm)
    {
        printf_output("Output directory Name:  %s\n",run_details->directory_name);
        printf_output("Threads:                %llu\n",run_details->threads_num);
        printf_output("fault model filename :  %s\n",run_details->fault_model_filename);
        printf_output("Start from checkpoint:  %s\n",run_details->start_from_checkpoint == 1 ? "Yes" : "No");
        if (run_details->start_from_checkpoint == 1)
        {
            printf_output("Checkpoints:            %llu\n",run_details->total_num_checkpoints);
        }
        printf_output("Max instructions:       %llu\n",run_details->max_instructions);
        printf_output("Stop on equivalence:    %s\n",run_details->stop_on_equivalence == 1 ? "Yes" : "No");
        printf_output("Time it:                %s\n",run_details->timeit == 1 ? "Yes" : "No");
        printf_output("Display disassembly:    %s\n",run_details->display_disassembly == 1 ? "Yes" : "No");
    }
}
void set_current_run_state_from_run_details(current_run_state_t* state,run_details_t* rd)
{
    state->start_from_checkpoint=rd->start_from_checkpoint;
    state->stop_on_equivalence=rd->stop_on_equivalence;
    state->run_mode=rd->run_mode;
    state->total_num_checkpoints=rd->total_num_checkpoints;
    state->directory=rd->directory_name;
    state->timeit=rd->timeit;
    state->max_instructions=rd->max_instructions;
    state->display_disassembly=rd->display_disassembly;
    state->file_fprintf=stdout;
}

int main(int argc, char **argv, char **envp)
{
    char *this_binary=argv[0];

    if (argc != 2)
        usage(this_binary);

    const char *json_run_filename=argv[1];
    run_details_t run_details;
    load_run_details(json_run_filename,&run_details);  
    print_run_file_details(&run_details); 
    load_configuration(run_details.json_filename);


    current_run_state_t current_run_state={0};
    current_run_state_init(&current_run_state);

    set_current_run_state_from_run_details(&current_run_state, &run_details);
    switch (run_details.run_mode)
    {
        case eGOLDEN_rm:
            goldenrun_it(&current_run_state);
            break;  
        case eGOLDENRUN_FULL_rm:
            goldenrun_full_it(&current_run_state);
            break;
        case eSTATS_rm:
            stats_it(&current_run_state);
            break;
        case eMEMHOOK_rm:
            memhook_it(&current_run_state);
            break;
        case eFAULT_rm:
        {
            run_list_t* run_list=parse(run_details.fault_model_filename);
            print_run_list(run_list);
            fault_it(&current_run_state,run_list,run_details.threads_num);
            free_run_list(run_list);   
            break;
        }
        case eDEBUG_rm:
            debug_it(&current_run_state);
            break;
        default:
            usage(this_binary);
            my_exit(-1);
    }
    extern void my_malloc_free_print();
    free_run_details(&run_details);
    free_current_run_state(&current_run_state);
    free_binary_file_details();
    my_malloc_free_print();

    #ifdef SHOW_MALLOC
        my_malloc_free_print();
    #endif
    printf("Finished.\n");
    my_exit(1);
}
