#ifndef UTILS_H_INCLUDED
#define UTILS_H_INCLUDED
    #include "state.h"
    #include "structs.h"
    
    void print_memory_and_stack            (line_details_t* line_details_array, uint64_t num);
    void print_current_run_state            (current_run_state_t* c);
    void print_fault_rule                   (FILE *fd,fault_rule_t *fault_rule);
    void print_fault_rule_no_newline        (FILE *fd,fault_rule_t *fault_rule);
    void print_fault_rule_with_address      (FILE *fd,fault_rule_t *fault_rule);

    uint32_t super_fast_hash                (const uint8_t * data, int len) ;

    uint64_t fault_reg                      (uint64_t mask, op_t fault_op, uint64_t tmp,uint64_t size);
    uint64_t IP_fault_skip         (op_t fault_op, uint64_t tmp,uint64_t size);
    void fault_instruction                  (uint64_t mask, op_t fault_op, uint8_t* in,uint8_t* out,uint64_t size, FILE* f);
    int hex_string_to_byte_array            (uint8_t* out_byte_array,const char *hex_string);
    void phex                               (FILE* fd,uint8_t* str, uint64_t len);
    void sphex                              (uint8_t* str, uint64_t len,char* strcmp);
    void phex_reverse                       (FILE* fd,uint8_t* str, uint64_t len);
    void set_bit                            (uint128_t* line_to_set, uint64_t bit_position);
    bool is_bit_set                         (uint128_t instruction_bit_line, uint64_t bit_position);
    bool file_exists                        (const char * filename);
    const char* operation_to_string         (op_t operation_type);
    const char* target_to_string            (fault_target target);
    op_t string_to_operation                (char* operation_str);
    void trim                               (char * str);
    char *decimal_to_binary                 (uint64_t n);

    void print_register_bitmap              (uint128_t reg_num);
    void print_all_registers                (uc_engine* uc,FILE* fd);
    void print_register                     (uc_engine* uc,FILE* fd,uint64_t reg);
    
    void print_binary2                      (FILE* fd,uint64_t number);
    void print_binary                       (size_t const size, void const * const ptr, FILE* fd);
    void print_memory                       (uc_engine* uc, FILE* fd);
    void print_stack                        (uc_engine* uc, FILE* fd);
    void print_stack_from_sp                (uc_engine* uc, FILE* fd, uint64_t stack_size_to_print);
    
    const char* lifespan_mode_to_string     (lifespan_mode  lsm);
    const char* run_state_to_string         (run_state rr);
    const char* run_mode_to_string          (run_mode rm);
    const char* human_size                  (uint128_t bytes); 
    void *my_malloc                         (size_t s, char* description);
    void *my_realloc                        (void* ptrptr, size_t s, char* description);
    void my_free                            (void* ptr, char* description);
    uint64_t address_hit                    (address_hit_counter_t* a,uint64_t address);
    
    uint64_t thumb_check_address            (uint64_t a);

    void print_binary_file_details          ();
    void my_exit                            (int exit_value);
    void convertToUppercase(char *givenStr);

#endif
