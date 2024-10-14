#include <unicorn/unicorn.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "utils.h"
#include "fileio.h"
#include "unicorn_engine.h"
#include "state.h"
#include "structs.h"

bool is_equivalent (uc_engine* uc,current_run_state_t* current_run_state)
{   
    // make the hashes
    int hash_count= 3 + binary_file_details->memory_other_count;  // context (1), main (2), stack (3), + Other
    uint32_t* hashes=my_malloc(sizeof(uint32_t)* (hash_count+1),"hashes");
    make_hash(uc, hashes);
    FILE* f= current_run_state->file_fprintf;

    fprintf_output(f,"Context: %x \n",hashes[0]);
    fprintf_output(f,"Main mem: %x \n",hashes[1]);
    fprintf_output(f,"Stack mem: %x \n",hashes[2]);

    fprintf_output(f,"State hash: ");
    for (int i=0;i<hash_count;i++)
    {
        fprintf(f,"%x",hashes[i]);
    }
    fprintf(f,"\n");

    int match=0;
    for (uint64_t i=0;i<current_run_state->equivalence_count;i++)
    {
        match=1;
        for (uint64_t j=0;j<hash_count;j++)
        {
            if (current_run_state->equivalences[i].hashes[j] != hashes[j])
            {
                match=0;
            }
        }
        
        if (match == 1)
        {
            //Add a new fault rule to the end of this equivalence
            uint64_t fc=current_run_state->equivalences[i].fault_count;
            if (fc == 0)
            {
                current_run_state->equivalences[i].faults=my_malloc(sizeof(fault_rule_t),"equivalences faults");
            }
            else
            {
                current_run_state->equivalences[i].faults=my_realloc(current_run_state->equivalences[i].faults,sizeof(fault_rule_t)*(fc+1),"equivalences faults");
            }
            if (current_run_state->fault_rule.opcode_filter_fault)
            {
                uint64_t len=strlen(current_run_state->fault_rule.opcode_filter_fault)+1;
                current_run_state->equivalences[i].faults[fc].opcode_filter_fault=my_malloc((sizeof(char)*(len+1)),"equivalences opcode filter fault");
                strcpy(current_run_state->equivalences[i].faults[fc].opcode_filter_fault,current_run_state->fault_rule.opcode_filter_fault);
            }
            memcpy(&current_run_state->equivalences[i].faults[fc],&current_run_state->fault_rule,sizeof(fault_rule_t));
            print_fault_rule(f,&current_run_state->equivalences[i].faults[fc]);

            current_run_state->equivalences[i].fault_count++;
            my_free(hashes, "hashes");
            return true;
        }
    }

    if (match == 0)
    {
        uint64_t count=current_run_state->equivalence_count;
        // add a new equivalence to the list as this one is unique
        // NO HASH MATCH - ADDING A NEW EQUIVALENCE
        if (count == 0)
        {
            current_run_state->equivalences=my_malloc(sizeof(equivalences_t),"equivalences");
        }
        else
        {
            current_run_state->equivalences=my_realloc(current_run_state->equivalences,sizeof(equivalences_t)*(count+1),"equivalences");
        }
        current_run_state->equivalences[count].hashes=my_malloc(sizeof(uint32_t)*(hash_count),"equivalences hashes");
        for (int j=0;j<hash_count;j++)
        {
            current_run_state->equivalences[count].hashes[j]=hashes[j];
        }
        current_run_state->equivalences[count].fault_count=1;
        current_run_state->equivalences[count].faults=my_malloc(sizeof(fault_rule_t),"equivalences faults");
        memcpy(current_run_state->equivalences[count].faults,&current_run_state->fault_rule,sizeof(fault_rule_t));

        // Increment the number of equivalences
        current_run_state->equivalence_count++;
    }
    my_free(hashes,"hashes");
    return false;
}


void make_hash(uc_engine*uc, uint32_t* hashes)
{
    int counter=0;

    // hash for context
    uc_context* context_temp;
    uc_context_alloc(uc,&context_temp);
    uc_context_save(uc,context_temp);
    struct uc_context_copy 
    {
        size_t size;
        uint8_t data[0];
	};
    struct uc_context_copy* context_memory_temp= (struct uc_context_copy*)context_temp;
    hashes[counter]=super_fast_hash(context_memory_temp->data,context_memory_temp->size);
    counter++;
    uc_context_free(context_temp);

    // hash for main memory
    uint8_t* memory_main_temp=MY_STACK_ALLOC(binary_file_details->memory_main.size);
    uc_mem_read(uc, binary_file_details->memory_main.address,memory_main_temp,binary_file_details->memory_main.size);
    hashes[counter]=super_fast_hash(memory_main_temp,binary_file_details->memory_main.size);
    counter++;

    // hash for stack
    uint64_t temp_size=binary_file_details->stack.size - 256; //HACKHACK
    uint8_t* memory_stack_temp=MY_STACK_ALLOC(temp_size);
    uc_mem_read(uc, binary_file_details->stack.address,memory_stack_temp,temp_size);
    hashes[counter]=super_fast_hash(memory_stack_temp,temp_size);
    counter++;

    // hashes for other memory
    uint8_t* memory_other_temp;
    for (int i=0;i<binary_file_details->memory_other_count;i++)
    {
        memory_other_temp=MY_STACK_ALLOC(binary_file_details->memory_other[i].size);
        uc_mem_read(uc, binary_file_details->memory_other[i].address,memory_other_temp,binary_file_details->memory_other[i].size);
        hashes[counter]=super_fast_hash(memory_other_temp,binary_file_details->memory_other[i].size);
        counter++;
    }
}