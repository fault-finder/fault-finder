#ifndef CONFIGURATION_H_INCLUDED
#define CONFIGURATION_H_INCLUDED
    #include <stdint.h>
    #include "structs.h"

    // #define PRINTINSTRUCTIONS    // DEBUGDEBUG - used for debugging when the output looks wrong.
    // #define SHOW_MALLOC          // DEBUGDEBUG - used to check memory management
    #define MY_STACK_ALLOC(s) alloca(s)
    #define printf_debug(format, ...)  printf("\t\t\t\t\t\t\t\t >> Debug: " format, ## __VA_ARGS__)
    
    #define printf_verbose(format, ...)  printf("verbose: " format, ## __VA_ARGS__)  //used for debuging 

    #define printf_output(format, ...)   printf(" >> " format, ## __VA_ARGS__)
    #define fprintf_output(f,format, ...)  fprintf(f," >> " format, ## __VA_ARGS__)
    #define fprintf_errors(f,format, ...)  fprintf(f," >! " format, ## __VA_ARGS__)
    #define EASE_OUT_POWER 1.25
    #define MAX_FLAGS 40
    #define MAX_REGISTERS 128
    #define MAX_OP_CODE_STRING_FILTER_SIZE 10
    #define BILLION  1000000000L
    #define DISPLAY_EVERY 10
    #define UC_ERR_CHECK(x) _uc_err_check(x, #x)
    #define NO_CHECKPOINT 0xFFFFDEAD
    #define get16bits(d) (*((const uint16_t *) (d)))
    #define MAX_NUM_OF_BYTES_IN_OPCODE 7   // used to align the output

    uc_err _uc_err_check(uc_err err, const char* expr);

    typedef enum  {ascii_format,hex_format} format_enum;
    typedef enum  {address_memory,sp_offset_memory} memory_type_enum;
    typedef enum  {register_loc,address_in_register_loc, relative_address_loc, fixed_address_loc} string_location_enum;

    typedef struct _run_detail_t
    {
        char* json_filename;
        char* fault_model_filename;
        char* directory_name;
        char* address_to_disassembly_filename;
        run_mode run_mode;
        bool start_from_checkpoint;
        bool stop_on_equivalence;
        bool timeit;
        bool display_disassembly;
        uint64_t max_instructions;
        uint64_t total_num_checkpoints;
        uint64_t threads_num;
    } run_details_t;

    typedef struct _overwrite_memory_t
    {
        memory_type_enum type;
        format_enum format;
        uint64_t length;
        uint8_t* byte_array;
        uint64_t address;
        int64_t sp_offset;
    } overwrite_memory_t;

    typedef struct _overwrite_register_t
    {
        uint64_t reg;
        uint64_t reg_value;
    } overwrite_register_t;


    typedef struct _skips_t
    {
        uint64_t address;
        uint64_t bytes;
    } skips_t;

    typedef struct _hard_stops_t
    {
        string_location_enum location;
        uint64_t address;
    } hard_stops_t;

    typedef struct _patches_t
    {
        uint64_t address;
        uint64_t length;
        uint8_t* byte_array;
    } patches_t;

    typedef struct _output_t
    {
        string_location_enum location;
        uint64_t reg;
        uint64_t address;
        uint64_t length;
        uint64_t offset;
    } output_t;

    typedef struct _memory_segment_t
    {
        uint64_t address;
        uint64_t size;
    } memory_segment_t;

    typedef struct _binary_file_details_t
    {
        char* binary_filename;
        char* code_buffer;
        size_t code_buffer_size;
        //unicorn architecture and modes
        int my_uc_arch;
        int my_uc_mode; 
        int my_uc_cpu; 
        //capstone architecture and modes        
        int my_cs_arch;
        int my_cs_mode; 
        //Different values for different architectures
        int my_pc_reg;
        int my_sp_reg;
        memory_segment_t memory_main;
        uint64_t code_offset;
        memory_segment_t stack;
        uint64_t stack_start_address;
        uint64_t memory_other_count;
        memory_segment_t* memory_other;
        uint64_t code_start_address;
        uint64_t code_end_address;
        uint64_t fault_start_address;
        uint64_t fault_end_address;
        overwrite_memory_t* set_memory;
        uint64_t set_memory_count;
        overwrite_register_t* set_registers;
        uint64_t set_registers_count;
        output_t* outputs;
        uint64_t outputs_count;
        hard_stops_t* hard_stops;
        uint64_t hard_stops_count;
        skips_t* skips;
        uint64_t skips_count;
        patches_t* patches;
        uint64_t patches_count;
        uint64_t timeout;
        bool filter_results;
        char* filter_value;
        uint64_t filter_value_len;
    } binary_file_details_t;

    void free_current_run_state(current_run_state_t* current_run_state );
    void free_binary_file_details();
    void free_run_details(run_details_t* rd);
    void free_run_list(run_list_t* run_list);
    void load_configuration(const char* json_binary_filename);
    void load_run_details(const char* json_run_filename,run_details_t* rd);


extern const binary_file_details_t* binary_file_details;

#endif
