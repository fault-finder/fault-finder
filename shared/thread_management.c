#include <unicorn/unicorn.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>
#include "structs.h"
#include "run.h"
#include "utils.h"
#include "fileio.h"
#include "thread_management.h"

void initialise_consume_context(consume_context_t *context,instruction_range_fault_t *instruction_range_fault,current_run_state_t* current_run_state)
{
    // Set all memory to 0
    memset(context, 0, sizeof(consume_context_t));
    pthread_mutex_init(&context->consume_data_lock, NULL);

    // Set up the context to point at the first operation
    context->current_instruction_range_fault=instruction_range_fault;

    if (context->current_instruction_range_fault != NULL)
    {
        context->instruction=context->current_instruction_range_fault->instruction_start;
        context->line_details_array=current_run_state->line_details_array;
        context->start_from_checkpoint=current_run_state->start_from_checkpoint;
        context->stop_on_equivalence=current_run_state->stop_on_equivalence;
        context->display_disassembly=current_run_state->display_disassembly;
        context->timeit=current_run_state->timeit;
        context->max_instructions=current_run_state->max_instructions;
        context->total_num_checkpoints=current_run_state->total_num_checkpoints;
        context->total_instrs=current_run_state->total_instruction_count;
    }

    // printf("context->current_instruction_range_fault.instruction_start: %li \n",context->current_instruction_range_fault->instruction_start);
    // printf("context->current_instruction_range_fault.instruction_end: %li \n",context->current_instruction_range_fault->instruction_end);
    // printf("context->instruction: %li \n",context->instruction);
    // printf("context->line_details_array: %li \n",context->line_details_array);
    // printf("context->start_from_checkpoint: %li \n",context->start_from_checkpoint);
    // printf("context->stop_on_equivalence: %li \n",context->stop_on_equivalence);
    // printf("context->timeit: %li \n",context->timeit);
    // printf("context->total_num_checkpoints: %li \n",context->total_num_checkpoints);
    // printf("context->total_instrs: %li \n",context->total_instrs);
}

void move_to_next(consume_context_t *context)
{
    context->instruction++;
    if (context->instruction > context->current_instruction_range_fault->instruction_end)
    {
        context->current_instruction_range_fault=context->current_instruction_range_fault->next;

        // Leave the context set up to point to the next operation
        if (context->current_instruction_range_fault != NULL)
        {
            context->instruction=context->current_instruction_range_fault->instruction_start;
        } 
    }
}