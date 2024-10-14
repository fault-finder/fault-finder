#ifndef _FILE_IO_H_
#define _FILE_IO_H_
    #include "structs.h"
    #include <stdint.h>
    const char *skip_past(const char *lineptr, char c);
    void print_run_list(run_list_t *run_list);
    run_list_t *parse(const char *filename);
    uint128_t get_registers_from_line(char *line);
    void get_instructions_from_line(const char *original_line, instruction_range_fault_t* instruction_range_fault );
    void save_memory_to_file(uc_engine* uc, const char* filename);
    void save_stack_to_file(uc_engine* uc, const char* filename);
    void save_current_context_to_file(uc_engine* uc, const char* filename);
    void save_context_to_file(uc_engine *uc, uc_context* c, const char *filename);
    size_t context_size(uc_context* c);
    void print_equivalence_list(current_run_state_t* current_run_state, uint64_t instruction);
#endif