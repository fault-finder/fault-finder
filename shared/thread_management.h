#ifndef _THREAD_MANAGEMENT_
#define _THREAD_MANAGEMENT_

typedef struct _consume_context_t
{
    instruction_range_fault_t *current_instruction_range_fault;
    uint64_t instruction;
    uint64_t total_instrs;
    pthread_mutex_t consume_data_lock;
    const char* code_buffer;
    uint64_t code_buffer_size;
    line_details_t* line_details_array;
    bool start_from_checkpoint;
    bool stop_on_equivalence;
    bool timeit;
    bool display_disassembly;
    uint64_t max_instructions;
    uint64_t total_num_checkpoints;
    char* directory;;
} consume_context_t;

typedef struct _context_and_thread_num_t
{
    consume_context_t* context;
    int thread_num;
} context_and_thread_num_t;


void initialise_consume_context(consume_context_t *context,instruction_range_fault_t *instruction_range_fault,current_run_state_t* current_run_state);

void move_to_next(consume_context_t *context);
#endif