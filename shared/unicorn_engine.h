#ifndef _UNICORN_ENGINE_H_
#define _UNICORN_ENGINE_H_
    #include <stdint.h>
    #include <inttypes.h>
    #include "structs.h"
    #include "configuration.h"
    #include <unicorn/unicorn.h>

    // //unicorn architecutre and modes
    void uc_restore_from_checkpoint(uc_engine *uc, current_run_state_t* current_run_state, uint64_t instr);
    void print_outputs(uc_engine *uc, current_run_state_t* current_run_state);
    void print_sp_and_pc(uc_engine *uc, current_run_state_t* current_run_state);
    void print_hooks(uc_engine *uc, current_run_state_t* current_run_state);
    void my_uc_engine_setup                 (uc_engine** uc,current_run_state_t* current_run_state,char* description);
    void my_uc_emu_stop                     (uc_engine* uc);
    void my_uc_engine_start             (uc_engine *uc, current_run_state_t *current_run_state, uint64_t max_instructions);
    uc_err my_uc_close                      (uc_engine* uc, current_run_state_t* current_run_state,char* description);
    void my_uc_hook_del                     (const char* function_name,uc_engine* uc, uc_hook hh, current_run_state_t* current_run_state);
    void my_uc_hook_add                     (const char* function_name,uc_engine *uc, uc_hook *hh, int type, void *callback,void *user_data, uint64_t begin, uint64_t end);
    //void my_uc_engine_reset(uc_engine *uc, const char *code_buffer, size_t filesize, current_run_state_t *current_run_state);
    void my_uc_engine_reset                 (uc_engine *uc, current_run_state_t *current_run_state);
    void current_run_state_reset            (current_run_state_t* current_run_state);
    void current_run_state_init             (current_run_state_t* current_run_state);
    void uc_engine_set_memory_inputs        (uc_engine *uc, current_run_state_t *current_run_state);
    void uc_engine_set_new_register_inputs  (uc_engine *uc, current_run_state_t *current_run_state);
    // reset masks
    void hook_count_instructions            (uc_engine *uc, uint64_t address, uint64_t size, void *user_data);
    void hook_placebo                       (uc_engine *uc, uint64_t address, uint64_t size, void *user_data);
    void hook_min_max_mod                   (uc_engine *uc, uint64_t address, uint64_t size, void *user_data);
    void hook_code_skips                    (uc_engine *uc, uint64_t address, uint64_t size, void *user_data);
     // printing hooks
    void hook_code_print_instructions       (uc_engine *uc, uint64_t address, uint64_t size, void *user_data);
    void hook_code_print_debug       (uc_engine *uc, uint64_t address, uint64_t size, void *user_data);
    
    void hook_code_print_fault_instructions (uc_engine *uc, uint64_t address, uint64_t size, void *user_data);
    int disassemble_instruction_and_print   (FILE* f,uint8_t* tmp,uint64_t size);
    void print_data_at_address              (uc_engine *uc, uint64_t address, uint64_t size, void *user_data);
    // stats hooks
    void hook_code_stats                    (uc_engine *uc, uint64_t address, uint64_t size, void *user_data);
    // delete hooks
    void delete_hook_code_fault_it_address  (uc_engine *uc, current_run_state_t *current_run_state);
    void delete_hook_code_fault_it (uc_engine *uc, current_run_state_t *current_run_state);
    void delete_hook_count_instructions     (uc_engine *uc, current_run_state_t *current_run_state);
    // add hooks
    void add_hook_code_fault_it_address                (uc_engine *uc, current_run_state_t* current_run_state, uint64_t address_to_fault);
    // fault hooks


    void hook_code_fault_it_address         (uc_engine *uc, uint64_t address, uint64_t size, void *user_data);

    // hooks for instruction faulting
    void hook_code_fault_it_instruction     (uc_engine *uc, uint64_t address, uint64_t size, void *user_data);
    void hook_lifespan_revert_instruction   (uc_engine *uc, uint64_t address, uint64_t size, void *user_data);
    void hook_lifespan_repeat_instruction   (uc_engine *uc, uint64_t address, uint64_t size, void *user_data);

    // hooks for register faulting
    void hook_code_fault_it_register        (uc_engine *uc, uint64_t address, uint64_t size, void *user_data);
    void hook_lifespan_revert_register      (uc_engine *uc, uint64_t address, uint64_t size, void *user_data);
    void hook_lifespan_repeat_register      (uc_engine *uc, uint64_t address, uint64_t size, void *user_data);

    // hooks for IP faulting
    void hook_code_fault_it_IP              (uc_engine *uc, uint64_t address, uint64_t size, void *user_data);
    void hook_lifespan_repeat_IP            (uc_engine *uc, uint64_t address, uint64_t size, void *user_data);
    // no revert for IP

    void hook_code_start_faults             (uc_engine *uc, uint64_t address, uint64_t size, void *user_data);
    void hook_code_stop_faults              (uc_engine *uc, uint64_t address, uint64_t size, void *user_data);
    void hook_code_hard_stop                (uc_engine *uc, uint64_t address, uint64_t size, void *user_data);
    void hook_code_start_address            (uc_engine *uc, uint64_t address, uint64_t size, void *user_data);
    void hook_code_end_address              (uc_engine *uc, uint64_t address, uint64_t size, void *user_data);
    void hook_code_equivalent               (uc_engine *uc, uint64_t address, uint64_t size, void *user_data);
    // other hooks
    void hook_insn                          (uc_engine *uc, uint64_t address, uint64_t size, uint64_t value, void *user_data);
    void hook_instruction_invalid           (uc_engine *uc, void *user_data);
    void hook_intr                          (uc_engine *uc, uint64_t int_no, void *user_data);
    void hook_block                         (uc_engine *uc, uc_mem_type type, uint64_t address, uint64_t size, uint64_t value, void *user_data);
    void hook_memory_invalid                (uc_engine *uc, uc_mem_type type, uint64_t address, uint64_t size, uint64_t value, void *user_data);
    bool hook_mem_write                     (uc_engine *uc, uc_mem_type type, uint64_t address, uint64_t size, uint64_t value, void *user_data);
    bool hook_mem_read_after                (uc_engine *uc, uc_mem_type type, uint64_t address, uint64_t size, uint64_t value, void *user_data);
#endif