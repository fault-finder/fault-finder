#ifndef STRUCTS_H_INCLUDED
#define STRUCTS_H_INCLUDED

    #include <pthread.h>
    #include <unicorn/unicorn.h>
    #include "state.h"

    #define OP_MNEMONIC_MAX_LENGTH 50
    #define MAX_LINE_LENGTH_DISSASSEMBLE_FILE 100
    #define MAX_INSTRUCTION_BUFFER_REPLACEMENT_SIZE 16
    #define uint128_t unsigned __int128

    typedef enum {eNOT_eSET_op=0,eAND_op=1, eOR_op=2, eXOR_op=3, eADD_op=4, eSKIP_op=5, eSET_op=6,eCLEAR_op=7,eFLIP_op=8} op_t;
    typedef enum {eNONE_lsm, eREPEAT_lsm, eREVERT_lsm} lifespan_mode;
    typedef enum {eNONE_rm,eGOLDEN_rm, eGOLDENRUN_FULL_rm, eMEMHOOK_rm,eCOUNT_INSTRUCTIONS_rm,eSTATS_rm, eFAULT_rm, eTEST_rm, eTIMING_CHECKPOINT_rm, eDEBUG_rm} run_mode;
    typedef enum {reg_ft,instruction_pointer_ft,instruction_ft} fault_target;
    typedef enum {NONE_rs,STARTED_rs,
                    STARTED_FROM_CHECKPOINT_rs,
                    FAULTED_rs,EQUIVALENT_rs, TIMED_OUT_rs, 
                    ERRORED_rs, INTERRUPT_rs, HARD_STOP_rs,END_ADDRESS_rs,END_ADDRESS_AND_FAULTED_rs,MAX_INSTRUCTIONS_REACHED_rs, INSTRUCTION_ERROR_rs} run_state; 

    typedef struct _lifespan_t 
    {
        lifespan_mode mode; 
        uint64_t count;        
        uint64_t live_counter;   
        uint64_t original_target_value; 
        uint8_t original_instruction_value[MAX_INSTRUCTION_BUFFER_REPLACEMENT_SIZE]; 
        uint64_t original_instruction_value_size;
    } lifespan_t;
    

    typedef struct _fault_rule_t 
    {
        uint64_t instruction;
        fault_target target;
        bool force;             // Will force the register to be changed - even if it's not used at that line number
        uint64_t number;        // eg reg number  - if reg number it's an index into MY ARRAY - not the unicorn codes for the registers
        char* opcode_filter_fault;
        op_t operation;
        uint64_t mask;
        bool set;
        uint64_t faulted_address;
        lifespan_t lifespan;
    } fault_rule_t;
    
    typedef struct _equivalences_t
    {
        uint32_t* hashes;
        fault_rule_t* faults;
        uint32_t fault_count;
    } equivalences_t;

    typedef struct _line_details_t
    {
        char op_mnemonic[OP_MNEMONIC_MAX_LENGTH];  
        bool equivalent;
        bool checkpoint;
        uint8_t* memory_main;   // For checkpoints
        uint8_t** memory_other; // For checkpoints
        uint8_t* stack;         // For checkpoints
        uint64_t nearest_checkpoint;
        uc_context* the_context;        
        uint128_t the_registers_used;
        uint64_t address;
        uint64_t size;
        uint64_t hit_count;
    } line_details_t;

    typedef struct function_item_t
    {
        struct function_item_t* next;
        char function_name[40];
        uc_hook function_hook;
    } function_item_t;

    typedef struct function_list_t
    {
        function_item_t *head, *tail;
    } function_list_t;

    typedef struct  _address_hit_counter_t
        {
        uint64_t min_address;
        uint64_t max_address;
        uint64_t mod_address;
        uint64_t* counter;
        } address_hit_counter_t;

    // Define the structure to hold the address and opcode, used when the disassembly is read from a file
    // Use for tricore testing because capstone doesn't disassemble tricore.
    typedef struct address_and_disassembly_t{
        unsigned int address;
        char op_mnemonic[OP_MNEMONIC_MAX_LENGTH];
        char rest_of_line[OP_MNEMONIC_MAX_LENGTH]; // Yes I know this isn't the mnemonic - but I'm lazy - and the define will do for both.
    } address_and_disassembly_t;

    typedef struct _run_state_t
    {
        char* directory;                // Where to output
        FILE* file_fprintf;             // Where to output
        run_mode run_mode;
        run_state run_state;
        uint64_t fault_instruction_min;
        uint64_t fault_instruction_max;
        uint64_t instruction_count;
        uint64_t total_instruction_count;
        uint64_t last_address;
        int in_fault_range;
        fault_rule_t fault_rule;
        uc_hook hk_start_faults;
        uc_hook hk_stop_faults;
        uc_hook hk_start_address;
        uc_hook hk_end_address;
        uc_hook hk_count_instructions;
        uc_hook hk_fault_address;
        uc_hook hk_fault_it;
        uc_hook hk_intr;
        uc_hook hk_insn; 
        uc_hook hk_print_instructions;
        uc_hook hk_memory_invalid;
        uc_hook hk_instruction_invalid;
        uc_hook hk_fault_lifespan;
        uc_hook hk_equivalent;
        uc_hook* hk_hard_stops; 
        uc_hook* hk_skips;     
        line_details_t* line_details_array;         // Used to start at a checkpoint rather than the beginning - stores the states
        bool start_from_checkpoint;                 //starts the run from the nearest checkpoint not the beginning
        bool stop_on_equivalence;
        bool timeit;
        bool display_disassembly;
        bool restart;
        bool get_disassembly_from_file;
        uint64_t restart_address;
        uint64_t max_instructions;
        uint64_t total_num_checkpoints;
        uint64_t time_to_run;
        uint64_t time_to_restore_checkpoint;
        equivalences_t* equivalences;
        uint64_t equivalence_count;
        function_list_t my_function_list;
        address_hit_counter_t* address_hit_counter;
        address_and_disassembly_t* addresses_and_disassembly_from_file;
        uint64_t addresses_and_disassembly_from_file_count;
    } current_run_state_t;

    typedef struct _operation_fault_t
    {
        op_t operation;
        uint64_t *masks;
        uint64_t mask_count;
        struct _operation_fault_t* next;
    } operation_fault_t;
    
    typedef struct _lifespan_fault_t
    {
        lifespan_t lifespan;
        operation_fault_t* operation_fault_head;
        struct _lifespan_fault_t* next;
    } lifespan_fault_t;

    typedef struct _opcode_filter_fault_t
    {
        char* string;
        lifespan_fault_t* lifespan_head;
        struct _opcode_filter_fault_t* next;
    } opcode_filter_fault_t;

    typedef struct _target_fault_t
    {
        fault_target target; // Currently: registers or instruction pointer or code
        bool force;  // will force the register to be faulted - even if it's not used in that instruction
        uint128_t register_bit;
        opcode_filter_fault_t* opcode_filter_fault_head;
        struct _target_fault_t* next;
    } target_fault_t;

    typedef struct _instruction_range_fault_t
    {
        uint64_t instruction_start;
        uint64_t instruction_end;
        target_fault_t* target_fault_head;
        struct _instruction_range_fault_t* next;
    } instruction_range_fault_t;

    typedef struct _run_list_t
    {
        instruction_range_fault_t* instruction_range_fault;
    } run_list_t;

    typedef struct _workload_t
    {
        instruction_range_fault_t* instruction_range_fault;
        uint64_t instruction;
    } workload_t;


#endif