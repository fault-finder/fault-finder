#ifndef _RUN_H_
#define _RUN_H_
#include "configuration.h"
void debug_it(current_run_state_t* current_run_state);
void goldenrun_it(current_run_state_t* current_run_state);
void goldenrun_full_it(current_run_state_t* current_run_state);
void memhook_it( current_run_state_t* current_run_state);
void stats_it(current_run_state_t* current_run_state);
void fault_it(current_run_state_t* current_run_state,run_list_t* run_list,uint64_t num_threads);
void* fault_it_thread(void* user_data,run_details_t* run_details);
void run_to_write_stats(current_run_state_t* current_run_state);
#endif