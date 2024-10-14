
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <json-c/json.h>
#include <capstone/capstone.h>
#include <sys/stat.h>
#include "configuration.h"
#include "utils.h"
#include "unicorn_consts.h"

static binary_file_details_t internal_binary_file_details={0};
const binary_file_details_t* binary_file_details=&internal_binary_file_details;

static run_details_t internal_run_details={0};
const run_details_t* run_details=&internal_run_details;


void free_run_details(run_details_t* rd)
{    
    my_free(rd->json_filename,"run details - json filename");
    if (rd->run_mode == eFAULT_rm)
    {
        my_free(rd->directory_name,"run details - directory_name");
        my_free(rd->fault_model_filename,"run details - fault model filename");
    }
}

void free_run_list(run_list_t* run_list)
{
    instruction_range_fault_t *current_instruction_range_fault=run_list->instruction_range_fault;
    instruction_range_fault_t *current_instruction_range_fault_to_free;
    while (current_instruction_range_fault != NULL)
    {
        //FAULTS
        target_fault_t *current_target_fault=current_instruction_range_fault->target_fault_head;
        target_fault_t *current_target_fault_to_free;
        while (current_target_fault != NULL)
        {
            //TARGETS            
            opcode_filter_fault_t *current_opcode_filter_fault=current_target_fault->opcode_filter_fault_head;
            opcode_filter_fault_t *current_opcode_filter_fault_to_free;
            while (current_opcode_filter_fault != NULL)
            {
                //OPCODE
                lifespan_fault_t *current_lifespan_fault=current_opcode_filter_fault->lifespan_head;
                lifespan_fault_t *current_lifespan_fault_to_free;
                while (current_lifespan_fault != NULL)
                {
                    //LIFESPAN AND operation list                  
                    operation_fault_t *current_operation=current_lifespan_fault->operation_fault_head;
                    operation_fault_t *operation_to_free;;
                    while (current_operation != NULL)
                    {
                        my_free(current_operation->masks,"masks");
                        operation_to_free=current_operation;
                        current_operation=current_operation->next;
                        my_free(operation_to_free,"operation_list");
                    }
                    current_lifespan_fault_to_free=current_lifespan_fault;
                    current_lifespan_fault=current_lifespan_fault->next;
                    my_free(current_lifespan_fault_to_free,"lifespan_fault_list");
                }
                current_opcode_filter_fault_to_free=current_opcode_filter_fault;
                current_opcode_filter_fault=current_opcode_filter_fault->next;
                if (current_opcode_filter_fault_to_free->string != NULL)
                {
                    my_free(current_opcode_filter_fault_to_free->string,"opcode_filter_fault_text");
                }
                my_free(current_opcode_filter_fault_to_free,"opcode_filter_fault");
            }
            current_target_fault_to_free=current_target_fault;
            current_target_fault=current_target_fault->next;
            my_free(current_target_fault_to_free,"target_fault");
        }
        current_instruction_range_fault_to_free=current_instruction_range_fault;
        current_instruction_range_fault=current_instruction_range_fault->next;
        my_free(current_instruction_range_fault_to_free,"instruction_range_fault");
    }
    my_free(run_list,"run_list");
}

void free_current_run_state(current_run_state_t* current_run_state )
{
    for (uint64_t i=1;i<current_run_state->total_instruction_count;i++)
    {
        if (current_run_state->line_details_array)
        {
            if (current_run_state->line_details_array[i].checkpoint == true)
            {
                uc_context_free(current_run_state->line_details_array[i].the_context);
            }
        }
    }
    my_free(current_run_state->line_details_array,"line_details_array");
    if (current_run_state->address_hit_counter != NULL)
    {
        my_free(current_run_state->address_hit_counter->counter,"hit counter array");
        my_free(current_run_state->address_hit_counter,"Address hit counter");
    }
    my_free(current_run_state->addresses_and_disassembly_from_file,"Addresses and disassembly from file");
}

void free_binary_file_details()
{

    my_free(internal_binary_file_details.binary_filename, "internal binary file details - binery_filename");
    my_free(internal_binary_file_details.skips,"internal binary file details - skips");
    my_free(internal_binary_file_details.hard_stops,"internal binary file details - hard_stops");
    my_free(internal_binary_file_details.set_registers,"internal binary file details - set registers");
    my_free(internal_binary_file_details.memory_other,"internal binary file details - memory other");
    my_free(internal_binary_file_details.outputs,"internal binary file details - outputs");

    for (uint64_t i=0;i < internal_binary_file_details.set_memory_count;i++)
    {
        my_free(internal_binary_file_details.set_memory[i].byte_array, "internal binary file details - set memory - byte_array");
    }
    my_free(internal_binary_file_details.set_memory,"internal binary file details - set memory");

    // patches
    for (uint64_t i=0;i < internal_binary_file_details.patches_count;i++)
    {
        my_free(internal_binary_file_details.patches[i].byte_array,"internal binary file details - patches - byte_array");
    }
    my_free(internal_binary_file_details.patches,"internal binary file details - patches");


    if (internal_binary_file_details.filter_value != NULL)
    {
        my_free(internal_binary_file_details.filter_value,"internal binary file details - filter value");
    }

    my_free(internal_binary_file_details.code_buffer,"internal binary file details - code buffer");
}

static void get_code_from_file()
{
    FILE *fp;
    #ifdef DEBUG
        printf("Binary file to run: %s\n",internal_binary_file_details.binary_filename);
    #endif
    struct stat sb;

    if (lstat(internal_binary_file_details.binary_filename, &sb) == -1) 
    {
        fprintf(stderr, "Error. File doesn't exist. \n >>> %s\n", internal_binary_file_details.binary_filename);
        my_exit(EXIT_FAILURE);
    }
    
    switch (sb.st_mode & S_IFMT) 
    {
        case S_IFBLK:  
            fprintf(stderr, "Error. Block Device has been suppied - not a file. \n >>> %s\n", internal_binary_file_details.binary_filename);
            my_exit(EXIT_FAILURE);
        case S_IFCHR:  
            printf("character device\n");        
            my_exit(EXIT_FAILURE);
        case S_IFDIR:  
            fprintf(stderr, "Error. Directory has been suppied - not a file. \n >>> %s\n", internal_binary_file_details.binary_filename);
            my_exit(EXIT_FAILURE);
            break;
        case S_IFIFO:  
            printf("FIFO/pipe\n");               
            my_exit(EXIT_FAILURE);
        case S_IFLNK:  
            printf("symlink\n");                 
            my_exit(EXIT_FAILURE);
        case S_IFSOCK: 
            printf("socket\n");                  
            my_exit(EXIT_FAILURE);
        case S_IFREG:  //regular file
            break;
        default:       
            fprintf(stderr, "Error. Unknown file type. \n >>> %s\n", internal_binary_file_details.binary_filename);
            my_exit(EXIT_FAILURE);
            break;
    }

    if ((fp=fopen(internal_binary_file_details.binary_filename, "rb")) == NULL)
    {
        fprintf(stderr, "Error opening file. \n >>> %s\n", internal_binary_file_details.binary_filename);
        my_exit(-1);
    }
    fseek(fp, 0, SEEK_END);
    internal_binary_file_details.code_buffer_size=ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (internal_binary_file_details.code_buffer_size == 0)
    {
        fprintf(stderr, "Does this file really contain a binary?\n >>> %s\n", internal_binary_file_details.binary_filename);
        my_exit(-1);
    }

    internal_binary_file_details.code_buffer=(char *)my_malloc(internal_binary_file_details.code_buffer_size,"internal binary file details - code buffer");
    fread(internal_binary_file_details.code_buffer, 1, internal_binary_file_details.code_buffer_size, fp);
    fclose(fp);    
}

void get_binary_filename(struct json_object *parsed_json )
{
    struct json_object *binary_filename;
    uint64_t temp_len;

    json_object_object_get_ex(parsed_json,"binary filename",&binary_filename);
    if (binary_filename == NULL)    
    {
        fprintf(stderr,"Error getting binary filename.\n");
        my_exit(-1);  
    }
    temp_len=json_object_get_string_len(binary_filename);
    // Checked - yes I do free this.
    internal_binary_file_details.binary_filename=my_malloc(temp_len+1,"internal_binary_file_details - binary_filename");
    strncpy(internal_binary_file_details.binary_filename,json_object_get_string(binary_filename),temp_len+1);
}

void get_memory_details(struct json_object *parsed_json)
{
    struct json_object *temp;
    json_object_object_get_ex(parsed_json,"memory address",&temp);
    if (temp == NULL)    
    {
        fprintf(stderr,"Error getting memory address.\n");
        my_exit(-1);  
    }
    internal_binary_file_details.memory_main.address=strtol(json_object_get_string(temp),NULL,0);

    json_object_object_get_ex(parsed_json,"memory size",&temp);
    if (temp == NULL)    
    {
        fprintf(stderr,"Error getting memory size.\n");
        my_exit(-1);  
    }
    internal_binary_file_details.memory_main.size=strtol(json_object_get_string(temp),NULL,0);

    // Check the size allocated is large enough 
    if (internal_binary_file_details.code_buffer_size > internal_binary_file_details.memory_main.size)
    {
        printf_output("Error. Main Memory is not large enough. Automatically adjusting\n");
        printf_output(" Main Memory size requested >>> 0x%" PRIx64 "\n", binary_file_details->memory_main.size);
        printf_output(" Binary File size actual >>> 0x%" PRIx64 "\n", (uint64_t)internal_binary_file_details.code_buffer_size);
        internal_binary_file_details.memory_main.size=internal_binary_file_details.code_buffer_size;
    }
}

void get_memory_other_details(struct json_object* parsed_json)
{
    struct json_object *all_other_memory=NULL;

    json_object_object_get_ex(parsed_json,"other memory",&all_other_memory);
    if (all_other_memory == NULL)    
    {
        return;   
    }
    internal_binary_file_details.memory_other_count=json_object_array_length(all_other_memory);
    internal_binary_file_details.memory_other=my_malloc(sizeof(memory_segment_t)*internal_binary_file_details.memory_other_count,"internal binary file details - memory other");

    struct json_object *next_memory_other=NULL;
    struct json_object *temp=NULL;

    // LOOP THROUGH ALL THE ARRAYS IN THE JSON FILE
    for (uint64_t i=0;i<internal_binary_file_details.memory_other_count;i++)
    {
        next_memory_other=json_object_array_get_idx(all_other_memory,i);

        // address
        json_object_object_get_ex(next_memory_other,"address",&temp);
        if (temp == NULL)    
        {
            fprintf(stderr,"Error getting address for %llu th memory other.\n",i);
            my_exit(-1);  
        }
        internal_binary_file_details.memory_other[i].address=strtol(json_object_get_string(temp),NULL,0);

        // size VALUE
        json_object_object_get_ex(next_memory_other,"size",&temp);
        if (temp == NULL)    
        {
            fprintf(stderr,"Error getting size  for %llu th memory other.\n",i);
            my_exit(-1);  
        }
        internal_binary_file_details.memory_other[i].size=strtol(json_object_get_string(temp),NULL,0);
    }
}


void get_code_offset (struct json_object *parsed_json)
{
    struct json_object *code_offset;
    json_object_object_get_ex(parsed_json,"code offset",&code_offset);
    if (code_offset == NULL)    
    {
        fprintf(stderr,"Error getting code offset.\n");
        my_exit(-1);  
    }
    internal_binary_file_details.code_offset=strtol(json_object_get_string(code_offset),NULL,0);

}

void get_code_ranges (struct json_object *parsed_json)
{
    struct json_object *temp;

    json_object_object_get_ex(parsed_json,"code start",&temp);
    if (temp == NULL)    
    {
        fprintf(stderr,"Error getting code start address.\n");
        my_exit(-1);  
    
    }
    internal_binary_file_details.code_start_address=strtol(json_object_get_string(temp),NULL,0);
    internal_binary_file_details.code_start_address+=internal_binary_file_details.memory_main.address;
    //internal_binary_file_details.code_start_address+=internal_binary_file_details.code_offset; just lose the whole 'offset' thing.

    json_object_object_get_ex(parsed_json,"code end",&temp);
    if (temp == NULL)    
    {
        fprintf(stderr,"Error getting code end address.\n");
        my_exit(-1);  
    }
    internal_binary_file_details.code_end_address=strtol(json_object_get_string(temp),NULL,0);
    internal_binary_file_details.code_end_address+=internal_binary_file_details.memory_main.address;
    //internal_binary_file_details.code_end_address+=internal_binary_file_details.code_offset;
    
    // set the code start/end and fault start/end to be exact not 'offsets'
    json_object_object_get_ex(parsed_json,"fault start",&temp);
    if (temp == NULL)    
    {
        fprintf(stderr,"Error getting fault start address.\n");
        my_exit(-1);  
    }
    internal_binary_file_details.fault_start_address=strtol(json_object_get_string(temp),NULL,0);
    internal_binary_file_details.fault_start_address+=internal_binary_file_details.memory_main.address;

    json_object_object_get_ex(parsed_json,"fault end",&temp);
    if (temp == NULL)    
    {
        fprintf(stderr,"Error getting fault end address.\n");
        my_exit(-1);  
    }
    internal_binary_file_details.fault_end_address=strtol(json_object_get_string(temp),NULL,0);
    internal_binary_file_details.fault_end_address+=internal_binary_file_details.memory_main.address;
}

void get_stack_details(struct json_object *parsed_json)
{
    struct json_object *temp;
    json_object_object_get_ex(parsed_json,"stack address",&temp);
    if (temp == NULL)    
    {
        fprintf(stderr,"Error getting stack address.\n");
        my_exit(-1);  
    }
    internal_binary_file_details.stack.address=strtol(json_object_get_string(temp),NULL,0);

    json_object_object_get_ex(parsed_json,"stack size",&temp);
    if (temp == NULL)    
    {
        fprintf(stderr,"Error getting stack size.\n");
        my_exit(-1);  
    }
    internal_binary_file_details.stack.size=strtol(json_object_get_string(temp),NULL,0);
    uint64_t stack_end = internal_binary_file_details.stack.address + internal_binary_file_details.stack.size;
    json_object_object_get_ex(parsed_json,"stack start",&temp);
    if (temp == NULL)    
    {
        printf_output("Note: No 'stack start' - automatically setting it to: 0x%" PRIx64 "\n",stack_end);
        internal_binary_file_details.stack_start_address= stack_end;
    }
    else
    {
        internal_binary_file_details.stack_start_address=strtol(json_object_get_string(temp),NULL,0);
        if (internal_binary_file_details.stack_start_address < internal_binary_file_details.stack.address || 
        internal_binary_file_details.stack_start_address >= stack_end )
        {
            fprintf(stderr,"Error stack start: 0x%" PRIx64 " is not inside the stack range: 0x%" PRIx64 " - 0x%" PRIx64 "\n",
                internal_binary_file_details.stack_start_address,
                internal_binary_file_details.stack.address,
                internal_binary_file_details.stack.address + internal_binary_file_details.stack.size);
            my_exit(-1);  
        }
    }
}

void get_cpu(struct json_object *parsed_json)
{
    struct json_object *temp;

    /********************************
    *        CPU
    ********************************/
    json_object_object_get_ex(parsed_json,"cpu",&temp);
    if (temp == NULL)    
    {
        fprintf(stderr,"Error getting 'cpu' value.\n");
        my_exit(-1);     
    }   
    const char* temp_arch=json_object_get_string(temp);
    internal_binary_file_details.my_uc_cpu = uc_cpu_from_name (temp_arch);
}

void get_arch_mode(struct json_object *parsed_json)
{
    struct json_object *temp;

    /********************************
    *        ARCHITECTURE
    ********************************/
    json_object_object_get_ex(parsed_json,"unicorn arch",&temp);
    if (temp == NULL)    
    {
        fprintf(stderr,"Error getting 'unicorn arch' value.\n");
        my_exit(-1);     
    }   
    const char* temp_arch=json_object_get_string(temp);
    internal_binary_file_details.my_uc_arch=unicorn_arch_int_from_name(temp_arch);
    switch (internal_binary_file_details.my_uc_arch)
    {
        case UC_ARCH_ARM:
            internal_binary_file_details.my_sp_reg=UC_ARM_REG_SP;
            internal_binary_file_details.my_pc_reg=UC_ARM_REG_PC;
            break;
        case UC_ARCH_ARM64:
            internal_binary_file_details.my_sp_reg=UC_ARM64_REG_SP;
            internal_binary_file_details.my_pc_reg=UC_ARM64_REG_PC;
            break;
        case UC_ARCH_RISCV:
            internal_binary_file_details.my_sp_reg=UC_RISCV_REG_SP;
            internal_binary_file_details.my_pc_reg=UC_RISCV_REG_PC;
            break;
        case UC_ARCH_TRICORE:
            internal_binary_file_details.my_sp_reg=UC_TRICORE_REG_SP;
            internal_binary_file_details.my_pc_reg=UC_TRICORE_REG_PC;
            break;
        case UC_ARCH_PPC:
            internal_binary_file_details.my_sp_reg=UC_PPC_REG_1;
            internal_binary_file_details.my_pc_reg=UC_PPC_REG_PC;
            break;
        case UC_ARCH_MIPS:
            internal_binary_file_details.my_sp_reg=UC_MIPS_REG_SP;
            internal_binary_file_details.my_pc_reg=UC_MIPS_REG_PC;
            break;
        case UC_ARCH_X86:
            internal_binary_file_details.my_sp_reg=UC_X86_REG_RSP;
            internal_binary_file_details.my_pc_reg=UC_X86_REG_RIP;
            break;
        default:
            fprintf(stderr,"No valid architecture. Received: %s. \n",temp_arch);
            my_exit(-1);
            break;
        };

    /********************************
    *   CAPSTONE  ARCHITECTURE
    ********************************/
    json_object_object_get_ex(parsed_json,"capstone arch",&temp);
    if (temp == NULL)    
    {
        fprintf(stderr,"Error getting 'capstone arch' value.\n");
        my_exit(-1);     
    }   
    const char* temp_capstone_arch=json_object_get_string(temp);
    internal_binary_file_details.my_cs_arch=capstone_arch_int_from_name(temp_capstone_arch);

    /********************************
     *          MODE
     ********************************/
    json_object_object_get_ex(parsed_json,"unicorn mode",&temp);
    if (temp == NULL)    
    {
        fprintf(stderr,"Error getting 'unicorn mode' value.\n");
        my_exit(-1);     
    }
    const char* temp_mode=json_object_get_string(temp);
    internal_binary_file_details.my_uc_mode=unicorn_mode_int_from_name(temp_mode);

    /********************************
     *          CAPSTONE MODE
     ********************************/
    json_object_object_get_ex(parsed_json,"capstone mode",&temp);
    if (temp == NULL)    
    {
        fprintf(stderr,"Error getting capstone mode value.\n");
        my_exit(-1);     
    }
    const char* temp_capstone_mode=json_object_get_string(temp);
    internal_binary_file_details.my_cs_mode=capstone_mode_int_from_name(temp_capstone_mode);
    
}

void get_patches(struct json_object* parsed_json)
{

    struct json_object *all_patches=NULL;

    json_object_object_get_ex(parsed_json,"patches",&all_patches);
    if (all_patches == NULL)    
    {
        printf_output("Note: No patched instructions.\n");
        return;
    }
    // How many patches are there
    internal_binary_file_details.patches_count=json_object_array_length(all_patches);
    internal_binary_file_details.patches=0;
    // Malloc the space for all the patches
    if (internal_binary_file_details.patches_count!=0)
    {
        internal_binary_file_details.patches=my_malloc(sizeof(patches_t)*internal_binary_file_details.patches_count,"internal binary file details - patches");

        struct json_object *next_patch=NULL;
        struct json_object *temp=NULL;

        // LOOP THROUGH ALL THE ARRAYS IN THE JSON FILE
        for (uint64_t i=0;i<internal_binary_file_details.patches_count;i++)
        {
            next_patch=json_object_array_get_idx(all_patches,i);

            // REG
            json_object_object_get_ex(next_patch,"address",&temp);
            if (temp == NULL)    
            {
                fprintf(stderr,"Error getting address for %llu th patch.\n",i);
                my_exit(-1);  
            }
            internal_binary_file_details.patches[i].address=strtol(json_object_get_string(temp),NULL,0);

            // byte_array & LENGTH for patches
            json_object_object_get_ex(next_patch,"byte array",&temp);
            if (temp == NULL)    
            {
                fprintf(stderr,"Error getting byte_array for %lluth patch. Did you forget to include a 'byte array' tag?\n",i);
                my_exit(-1);  
            }

            internal_binary_file_details.patches[i].length=json_object_get_string_len(temp);
            if (internal_binary_file_details.patches[i].length %2 != 0)
            {
                fprintf(stderr,"Error getting byte_array for %lluth patch. byte_array is not an even number of hex digits.?\n",i);
                my_exit(-1);  
            }

            internal_binary_file_details.patches[i].length=internal_binary_file_details.patches[i].length/2;
            internal_binary_file_details.patches[i].byte_array=(uint8_t*) my_malloc ((internal_binary_file_details.patches[i].length+1),"internal binary file details - set patches - byte_array");
            hex_string_to_byte_array(internal_binary_file_details.patches[i].byte_array,json_object_get_string(temp));
        }
    }
}

void get_skips(struct json_object* parsed_json)
{
    struct json_object *all_skips=NULL;

    json_object_object_get_ex(parsed_json,"skips",&all_skips);
    if (all_skips == NULL)    
    {
        printf_output("Note: No skipped instructions defined.\n");
        return;
    }
    internal_binary_file_details.skips_count=json_object_array_length(all_skips);
    internal_binary_file_details.skips=my_malloc(sizeof(skips_t)*internal_binary_file_details.skips_count,"internal binary file details - skips");


    struct json_object *next_skip=NULL;
    struct json_object *temp=NULL;

    // LOOP THROUGH ALL THE ARRAYS IN THE JSON FILE
    for (uint64_t i=0;i<internal_binary_file_details.skips_count;i++)
    {
        next_skip=json_object_array_get_idx(all_skips,i);

        // REG
        json_object_object_get_ex(next_skip,"address",&temp);
        if (temp == NULL)    
        {
            fprintf(stderr,"Error getting address for %llu th skips.\n",i);
            my_exit(-1);  
        }
        internal_binary_file_details.skips[i].address=strtol(json_object_get_string(temp),NULL,0);

        // REG VALUE
        json_object_object_get_ex(next_skip,"bytes",&temp);
        if (temp == NULL)    
        {
            fprintf(stderr,"Error getting bytes value for %lluth skip. Did you forget the 'bytes' tag?\n",i);
            my_exit(-1);  
        }
        internal_binary_file_details.skips[i].bytes=strtol(json_object_get_string(temp),NULL,0);
    }
}

void get_hard_stops(struct json_object* parsed_json)
{
    struct json_object *all_hard_stops=NULL;

    json_object_object_get_ex(parsed_json,"hard stops",&all_hard_stops);
    if (all_hard_stops == NULL)    
    {
        internal_binary_file_details.hard_stops_count=0;
        return;
    }
    internal_binary_file_details.hard_stops_count=json_object_array_length(all_hard_stops);
    internal_binary_file_details.hard_stops=my_malloc(sizeof(skips_t)*internal_binary_file_details.hard_stops_count,"internal binary file details - hard stops");
    struct json_object *next_hard_stop=NULL;
    struct json_object *temp=NULL;

    // LOOP THROUGH ALL THE ARRAYS IN THE JSON FILE
    for (uint64_t i=0;i<internal_binary_file_details.hard_stops_count;i++)
    {
        next_hard_stop=json_object_array_get_idx(all_hard_stops,i);

        json_object_object_get_ex(next_hard_stop,"location",&temp);
        if (temp == NULL)    
        {
            fprintf(stderr,"Error getting location for %lluth hard_stop.\n",i);
            my_exit(-1);  
        }
	internal_binary_file_details.hard_stops[i].location=relative_address_loc;
	if (strcmp(json_object_get_string(temp),"fixed address") == 0)
        {
            internal_binary_file_details.hard_stops[i].location=fixed_address_loc;
        }
	
        // address
        json_object_object_get_ex(next_hard_stop,"address",&temp);
        if (temp == NULL)    
        {
            fprintf(stderr,"Error getting address for %llu th hard stop.\n",i);
            my_exit(-1);
        }
        internal_binary_file_details.hard_stops[i].address=strtol(json_object_get_string(temp),NULL,0);
    }
}

void get_set_memory(struct json_object* parsed_json)
{
    struct json_object *set_memory=NULL;
    json_object_object_get_ex(parsed_json,"set memory",&set_memory);
    if (set_memory == NULL)    
    {
        fprintf(stderr,"Error getting set memory.\n");
        my_exit(-1);     
    }
    internal_binary_file_details.set_memory_count=json_object_array_length(set_memory);
    internal_binary_file_details.set_memory=my_malloc(sizeof(overwrite_memory_t)*internal_binary_file_details.set_memory_count,"internal binary file details - set memory");

    struct json_object *next_memory_item=NULL;
    struct json_object *temp=NULL;

    // LOOP THROUGH ALL THE ARRAYS IN THE JSON FILE
    for (uint64_t i=0;i<internal_binary_file_details.set_memory_count;i++)
    {
        next_memory_item=json_object_array_get_idx(set_memory,i);

        // FORMAT
        json_object_object_get_ex(next_memory_item,"format",&temp);
        if (temp == NULL)    
        {
            fprintf(stderr,"Error getting format for %lluth set memory. Did you forget to include a 'format' tag?\n",i);
            my_exit(-1);  
        }
        if (strcmp(json_object_get_string(temp),"hex") == 0)
        {
            internal_binary_file_details.set_memory[i].format=hex_format;
        }
        else if (strcmp(json_object_get_string(temp),"ascii") == 0)
        {
            internal_binary_file_details.set_memory[i].format=ascii_format;
        }
        else
        {
            fprintf(stderr,"No valid format set for %lluth set memory. Options are 'hex' or 'ascii'\n",i);
            my_exit(-1);
        }

        // byte_array & LENGTH
        json_object_object_get_ex(next_memory_item,"byte array",&temp);
        if (temp == NULL)    
        {
            fprintf(stderr,"Error getting byte_array for %lluth set memory. Did you forget to include a 'byte array' tag?\n",i);
            my_exit(-1);  
        }

        if (internal_binary_file_details.set_memory[i].format == hex_format)
        {
            internal_binary_file_details.set_memory[i].length=json_object_get_string_len(temp)/ 2;
            internal_binary_file_details.set_memory[i].byte_array=(uint8_t*) my_malloc ((internal_binary_file_details.set_memory[i].length+1),"internal binary file details - set memory - byte_array");
            hex_string_to_byte_array(internal_binary_file_details.set_memory[i].byte_array,json_object_get_string(temp));
        }
        else 
        {
            internal_binary_file_details.set_memory[i].length=json_object_get_string_len(temp);
            // Checked - yes I do free this.
            internal_binary_file_details.set_memory[i].byte_array=my_malloc((sizeof(char))*(internal_binary_file_details.set_memory[i].length+1),"internal binary file details - set memory - byte_array");
            // Checked - yes I do free this.
            memcpy(internal_binary_file_details.set_memory[i].byte_array,json_object_get_string(temp),internal_binary_file_details.set_memory[i].length+1);
        }

        //TYPE
        json_object_object_get_ex(next_memory_item,"type",&temp);
        if (temp == NULL)    
        {
            fprintf(stderr,"Error getting json tag 'type' for %llu th new input (Should be 'address' or 'sp offset').\n",i);
            my_exit(-1);  
        }

        if (strcmp(json_object_get_string(temp),"address") == 0)
        {
            // ADDRESS
            internal_binary_file_details.set_memory[i].sp_offset=0;
            internal_binary_file_details.set_memory[i].type=address_memory;
            json_object_object_get_ex(next_memory_item,"address",&temp);
            if (temp == NULL)    
            {
                fprintf(stderr,"Error getting address for %llu th new input. Did you include an 'address' tag?\n",i);
                my_exit(-1);  
            }
            internal_binary_file_details.set_memory[i].address=strtol(json_object_get_string(temp),NULL,0);
        }
        else if (strcmp(json_object_get_string(temp),"sp_offset") == 0)
        {
            // SP OFFSET
            internal_binary_file_details.set_memory[i].address=0;
            internal_binary_file_details.set_memory[i].type=sp_offset_memory;
            json_object_object_get_ex(next_memory_item,"sp_offset",&temp);
            if (temp == NULL)    
            {
                fprintf(stderr,"Error getting sp_offset for %llu th new input. Did you include an 'sp_offset' tag?",i);
                my_exit(-1);  
            }
            internal_binary_file_details.set_memory[i].sp_offset=strtol(json_object_get_string(temp),NULL,0);
        }
        else
        {
            fprintf(stderr,"Error -  type for %llu th new input (should be 'address' or 'sp_offset').\n",i);
            my_exit(-1);  
        }
        
    }
}

void get_set_registers(struct json_object* parsed_json)
{
    struct json_object *set_registers=NULL;
    //struct json_object *new_register=NULL;

    json_object_object_get_ex(parsed_json,"set registers",&set_registers);
    if (set_registers == NULL)    
    {
        fprintf(stderr,"Error getting set registers.\n");
        my_exit(-1);     
    }
    internal_binary_file_details.set_registers_count=json_object_array_length(set_registers);
    internal_binary_file_details.set_registers=my_malloc(sizeof(overwrite_register_t)*internal_binary_file_details.set_registers_count,"internal binary file details - set registers");

    struct json_object *next_register=NULL;
    struct json_object *temp=NULL;

    // LOOP THROUGH ALL THE ARRAYS IN THE JSON FILE
    for (uint64_t i=0;i<internal_binary_file_details.set_registers_count;i++)
    {
        next_register=json_object_array_get_idx(set_registers,i);

        // REG
        json_object_object_get_ex(next_register,"reg",&temp);
        if (temp == NULL)    
        {
            fprintf(stderr,"Error getting reg for %llu th set registers. Use 'reg'.\n",i);
            my_exit(-1);  
        }
        const char* reg_name_temp=json_object_get_string(temp);
        internal_binary_file_details.set_registers[i].reg=register_int_from_name(reg_name_temp);

        // REG VALUE
        json_object_object_get_ex(next_register,"reg value",&temp);
        if (temp == NULL)    
        {
            fprintf(stderr,"Error getting reg value for %llu th new register. Use 'reg value'\n",i);
            my_exit(-1);  
        }
        internal_binary_file_details.set_registers[i].reg_value=strtol(json_object_get_string(temp),NULL,0);
    }
}

void get_outputs(struct json_object* parsed_json)
{
    struct json_object *outputs=NULL;

    json_object_object_get_ex(parsed_json,"outputs",&outputs);
    if (outputs == NULL)    
    {
        fprintf(stderr,"Error getting outputs.\n");
        my_exit(-1);     
    }
    internal_binary_file_details.outputs_count=json_object_array_length(outputs);
    internal_binary_file_details.outputs=my_malloc(sizeof(output_t)*internal_binary_file_details.outputs_count,"internal binary file details - outputs");


    struct json_object *next_output=NULL;
    struct json_object *temp=NULL;

    // LOOP THROUGH ALL THE ARRAYS IN THE JSON FILE
    for (uint64_t i=0;i<internal_binary_file_details.outputs_count;i++)
    {
        next_output=json_object_array_get_idx(outputs,i);
        json_object_object_get_ex(next_output,"location",&temp);
        if (temp == NULL)    
        {
            fprintf(stderr,"Error getting location for %lluth output.\n",i);
            my_exit(-1);  
        }
        if (strcmp(json_object_get_string(temp),"register") == 0)
        {
            internal_binary_file_details.outputs[i].location=register_loc;
        }
        else if (strcmp(json_object_get_string(temp),"relative address") == 0)
        {
            internal_binary_file_details.outputs[i].location=relative_address_loc;
        }
        else if (strcmp(json_object_get_string(temp),"fixed address") == 0)
        {
            internal_binary_file_details.outputs[i].location=fixed_address_loc;
        }
        else if (strcmp(json_object_get_string(temp),"address in register") == 0)
        {
            internal_binary_file_details.outputs[i].location=address_in_register_loc;
        }
        else
        {
            fprintf(stderr,"No valid format set for %lluth output. Received: %s\n",i,json_object_get_string(temp));
            fprintf(stderr,"Valid outputs are: register, relative address, fixed address, address in register.\n");
            my_exit(-1);
        }

        if ( internal_binary_file_details.outputs[i].location == register_loc || internal_binary_file_details.outputs[i].location == address_in_register_loc)
        {
            // reg         
            json_object_object_get_ex(next_output,"register",&temp);
            if (temp == NULL)    
            {
                fprintf(stderr,"Error getting register for %lluth output.\n",i);
                my_exit(-1);  
            }
            const char* reg_name=json_object_get_string(temp);
            internal_binary_file_details.outputs[i].reg=register_int_from_name(reg_name);
        }
        if ( internal_binary_file_details.outputs[i].location == relative_address_loc || internal_binary_file_details.outputs[i].location == fixed_address_loc)
        {
            // address         
            json_object_object_get_ex(next_output,"address",&temp);
            if (temp == NULL)    
            {
                fprintf(stderr,"Error getting address for %lluth output.\n",i);
                my_exit(-1);  
            }
            internal_binary_file_details.outputs[i].address=strtol(json_object_get_string(temp),NULL,0);
        }
        // length         
        json_object_object_get_ex(next_output,"length",&temp);
        if (temp == NULL)    
        {
            fprintf(stderr,"Error getting length for %lluth output.\n",i);
            my_exit(-1);  
        }
        internal_binary_file_details.outputs[i].length=strtol(json_object_get_string(temp),NULL,0);

        // offset         
        json_object_object_get_ex(next_output,"offset",&temp);
        if (temp == NULL)    
        {
            fprintf(stderr,"Error getting offest for %lluth output.\n",i);
            my_exit(-1);  
        }
        internal_binary_file_details.outputs[i].offset=strtol(json_object_get_string(temp),NULL,0);
    }
}

void get_new_timeout(struct json_object* parsed_json)
{
    struct json_object *timeout=NULL;
    json_object_object_get_ex(parsed_json,"timeout",&timeout);
    if (timeout == NULL)    
    {
        fprintf(stderr,"Error getting timeout value.\n");
        my_exit(-1);     
    }
    internal_binary_file_details.timeout=strtol(json_object_get_string(timeout),NULL,0);
}

void get_filter_results(struct json_object* parsed_json)
{
    struct json_object *filter_results=NULL;
    json_object_object_get_ex(parsed_json,"filter results",&filter_results);
    if (filter_results == NULL)    
    {
        fprintf(stderr,"Error getting filter results\n");
        my_exit(-1);     
    }
    if (strcmp(json_object_get_string(filter_results),"yes") == 0)
    {
        internal_binary_file_details.filter_results=true;
    }
    else if (strcmp(json_object_get_string(filter_results),"no") == 0)
    {
        internal_binary_file_details.filter_results=false;
    }
    else
    {
        fprintf(stderr,"Invalid filter results\n");
        my_exit(-1);
    }
    if (internal_binary_file_details.filter_results == true)
    {
        struct json_object *filter_value=NULL;
        json_object_object_get_ex(parsed_json,"filter results",&filter_value);
        if (filter_value == NULL)    
        {
            fprintf(stderr,"Error getting filter value\n");
            my_exit(-1);     
        }

        internal_binary_file_details.filter_value_len=json_object_get_string_len(filter_value);
            // Checked - yes I do free this.
        internal_binary_file_details.filter_value=my_malloc(sizeof(char)* (internal_binary_file_details.filter_value_len+1),"internal binary file details - filter value");
            // Checked - yes I do free this.
        strncpy(internal_binary_file_details.filter_value,json_object_get_string(filter_value),internal_binary_file_details.filter_value_len+1);
    }
    else
    {
        internal_binary_file_details.filter_value=NULL;
    }
    
}

void load_configuration(const char* json_binary_filename)
{
  FILE *fp = 0;
#define BUFFER_SIZE (65536UL)
    char buffer[BUFFER_SIZE]={0}; 
    struct json_object *parsed_json=NULL;
    if ((fp=fopen(json_binary_filename, "r")) == NULL)
    {
        fprintf(stderr,"Error opening json file: %s.\n",json_binary_filename);
        my_exit(-1);
    }
    fseek(fp,0,SEEK_END);
    long file_size=ftell(fp);
    fseek(fp,0,SEEK_SET);
    if (file_size > BUFFER_SIZE)
    {
        fprintf(stderr,"json file is larger than the buffer size.\n");
        my_exit(-1);
    }
    
    fread(buffer,BUFFER_SIZE,1,fp);
    fclose(fp);

    parsed_json=json_tokener_parse(buffer);
    if (parsed_json == NULL)    
    {
        fprintf(stderr,"Error parsing json file: %s. Check for missing commas.\n",json_binary_filename);
        my_exit(-1);  
    }

    /********************************
     *     binary filename
     ********************************/
    get_binary_filename(parsed_json);
    get_code_from_file();
    
    /********************************
     *     memory address & size
     ********************************/
    get_memory_details(parsed_json);

    /********************************
     *     other memory
     ********************************/
    get_memory_other_details(parsed_json);

    /********************************
     *    code offset
     ********************************/
    get_code_offset(parsed_json);

    /********************************
     *      code start & end
     *      fault start & end
     ********************************/
    get_code_ranges(parsed_json);

    /********************************
     *   stack
     ********************************/
    get_stack_details(parsed_json);
    /********************************
     *   arch
     ********************************/
    get_arch_mode(parsed_json);
    /********************************
     *   cpu
     ********************************/
    get_cpu(parsed_json);

    /********************************
     *      OUTPUS
     ********************************/
    get_outputs(parsed_json);

    /********************************
     *  SKIP ADDRESSES & SKIP BYTES
     ********************************/
    get_skips(parsed_json);
    get_patches(parsed_json);

    /********************************
     *  hard stops
     ********************************/
    get_hard_stops(parsed_json);

    /********************************
     *           set memory
     ********************************/
    get_set_memory(parsed_json);

    /********************************
     *           set registers
     ********************************/
    get_set_registers(parsed_json);

    /********************************
     *        TIME OUT
     ********************************/
    get_new_timeout(parsed_json);

    /********************************
     *        filter results
     *****************************/
    get_filter_results(parsed_json);
}

void get_binary_json_filename(struct json_object *parsed_json ,run_details_t* rd)
{
    struct json_object *binary_json_filename;
    uint64_t temp_len;

    json_object_object_get_ex(parsed_json,"binary json filename",&binary_json_filename);
    if (binary_json_filename == NULL)    
    {
        fprintf(stderr,"Error getting binary json filename. Check you have the name/value pair: 'binary json filename'\n");
        my_exit(-1);  
    }
    temp_len=json_object_get_string_len(binary_json_filename);
    rd->json_filename=my_malloc(temp_len+1,"run details - json filename");
    strncpy(rd->json_filename,json_object_get_string(binary_json_filename),temp_len+1);
}

void get_mode(struct json_object *parsed_json ,run_details_t* rd)
{
    struct json_object *temp;
    json_object_object_get_ex(parsed_json,"mode",&temp);
    if (temp == NULL)    
    {
        fprintf(stderr,"Error getting mode value.\n");
        my_exit(-1);     
    }

    if (strcmp(json_object_get_string(temp),"goldenrun") == 0)
    {
        rd->run_mode=eGOLDEN_rm;
    }
    else if (strcmp(json_object_get_string(temp),"goldenrun_full") == 0)
    {
        rd->run_mode=eGOLDENRUN_FULL_rm;
    }
    else if (strcmp(json_object_get_string(temp),"memhook") == 0)
    {
        rd->run_mode=eMEMHOOK_rm;
    }
    else if (strcmp(json_object_get_string(temp),"stats") == 0)
    {
        rd->run_mode=eSTATS_rm;
    }
    else if (strcmp(json_object_get_string(temp),"fault") == 0)
    {
        rd->run_mode=eFAULT_rm;
    }
    else if (strcmp(json_object_get_string(temp),"test") == 0)
    {
        rd->run_mode=eTEST_rm;
    }
        else if (strcmp(json_object_get_string(temp),"debug") == 0)
    {
        rd->run_mode=eDEBUG_rm;
    }
    else
    {
        fprintf(stderr,"No valid mode. Received: %s. \n", json_object_get_string(temp));
        fprintf(stderr,"Valid modes are: goldenrun, goldenrun_full, stats, fault, memhook and test.\n");
        my_exit(-1);
    }
}
    
void get_threads(struct json_object *parsed_json,run_details_t* rd)
{
    struct json_object *threads;
    json_object_object_get_ex(parsed_json,"threads",&threads);
    if (threads == NULL)    
    {
        fprintf(stderr,"Error getting number of threads.\n");
        my_exit(-1);  
    }
    rd->threads_num=strtol(json_object_get_string(threads),NULL,0);
    if (rd->threads_num == 0)
    {
        fprintf(stderr,"Number of threads cannot be 0!\n");
        my_exit(-1);       
    }
}

void get_max_instructions(struct json_object *parsed_json,run_details_t* rd)
{
    struct json_object *max_instructions;
    json_object_object_get_ex(parsed_json,"max instructions",&max_instructions);
    if (max_instructions == NULL)    
    {
        fprintf(stderr,"Error getting number of 'max instructions' - check you have a json tag for this.\n");
        my_exit(-1);  
    }
    rd->max_instructions=strtol(json_object_get_string(max_instructions),NULL,0);
}

void get_display_disassembly(struct json_object *parsed_json ,run_details_t* rd)
{
    struct json_object *disaply_disassembly;
    json_object_object_get_ex(parsed_json,"display disassembly",&disaply_disassembly);
    if (disaply_disassembly == NULL)    
    {
        fprintf(stderr,"Error getting 'display disassembly' value (use yes or no).\n");
        my_exit(-1);     
    }

    if (strcmp(json_object_get_string(disaply_disassembly),"yes") == 0)
    {
        rd->display_disassembly=true;
    }
    else if (strcmp(json_object_get_string(disaply_disassembly),"no") == 0)
    {
        rd->display_disassembly=false;
    }
    else 
    {
        fprintf(stderr,"Error getting 'display disassembly' value (use yes or no).\n");
        my_exit(-1);     
    }
}

void get_timeit(struct json_object *parsed_json ,run_details_t* rd)
{
    struct json_object *timeit;
    json_object_object_get_ex(parsed_json,"timeit",&timeit);
    if (timeit == NULL)    
    {
        fprintf(stderr,"Error getting timeit value (use yes or no).\n");
        my_exit(-1);     
    }

    if (strcmp(json_object_get_string(timeit),"yes") == 0)
    {
        rd->timeit=true;
    }
    else if (strcmp(json_object_get_string(timeit),"no") == 0)
    {
        rd->timeit=false;
    }
    else 
    {
        fprintf(stderr,"Error getting timeit value (use yes or no).\n");
        my_exit(-1);     
    }
}

void get_output_directory_name(struct json_object *parsed_json,run_details_t* rd)
{
    struct json_object *output_directory_name;
    uint64_t temp_len;

    json_object_object_get_ex(parsed_json,"output directory name",&output_directory_name);
    if (output_directory_name == NULL)    
    {
        fprintf(stderr,"Error getting diretory name .\n");
        my_exit(-1);  
    }
    temp_len=json_object_get_string_len(output_directory_name);
    // Checked - yes I do free this.
    rd->directory_name=my_malloc(temp_len+1,"run details - directory_name");
    strncpy(rd->directory_name,json_object_get_string(output_directory_name),temp_len+1);
}

void get_fault_model_filename(struct json_object *parsed_json ,run_details_t* rd)
{
    struct json_object *fault_model_filename;
    uint64_t temp_len;

    json_object_object_get_ex(parsed_json,"fault model filename",&fault_model_filename);
    if (fault_model_filename == NULL)    
    {
        fprintf(stderr,"Error getting rules filename.\n");
        my_exit(-1);  
    }
    temp_len=json_object_get_string_len(fault_model_filename);
    rd->fault_model_filename=my_malloc(temp_len+1,"run details - fault model filename");
    strncpy(rd->fault_model_filename,json_object_get_string(fault_model_filename),temp_len+1);
}

void get_checkpoints(struct json_object *parsed_json ,run_details_t* rd)
{
    struct json_object *checkpoints;
    json_object_object_get_ex(parsed_json,"checkpoints",&checkpoints);
    if (checkpoints == NULL)    
    {
        fprintf(stderr,"Error getting checkpoint value (use yes or no).\n");
        my_exit(-1);     
    }

    if (strcmp(json_object_get_string(checkpoints),"yes") == 0)
    {
        rd->start_from_checkpoint=true;
    }
    else if (strcmp(json_object_get_string(checkpoints),"no") == 0)
    {
        rd->start_from_checkpoint=false;
    }
    else
    {
        fprintf(stderr,"Error getting checkpoint value (use yes or no).\n");
        my_exit(-1);     
    }
}

void get_num_checkpoints(struct json_object *parsed_json,run_details_t* rd)
{
    struct json_object *num_checkpoints;
    json_object_object_get_ex(parsed_json,"number of checkpoints",&num_checkpoints);
    if (num_checkpoints == NULL)    
    {
        fprintf(stderr,"Error getting number of checkpoints to create.\n");
        my_exit(-1);  
    }
    rd->total_num_checkpoints=strtol(json_object_get_string(num_checkpoints),NULL,0);
}

void get_equivalents(struct json_object *parsed_json ,run_details_t* rd)
{
    struct json_object *equivalents;
    json_object_object_get_ex(parsed_json,"equivalents",&equivalents);
    if (equivalents == NULL)    
    {
        fprintf(stderr,"Error getting equivalents value (use yes or no).\n");
        my_exit(-1);     
    }

    if (strcmp(json_object_get_string(equivalents),"yes") == 0)
    {
        rd->stop_on_equivalence=true;
    }
    else if (strcmp(json_object_get_string(equivalents),"no") == 0)
    {
        rd->stop_on_equivalence=false;
    }
    else
    {
        fprintf(stderr,"Error getting equivalents value (use yes or no).\n");
        my_exit(-1);     
    }
}

void load_run_details(const char* json_run_filename,run_details_t* rd)
{
    FILE *fp=0;
    char buffer[8192]={0}; 
    struct json_object *parsed_json=NULL;

    if ((fp=fopen(json_run_filename, "r")) == NULL)
    {
        fprintf(stderr,"Error opening json file: %s.\n",json_run_filename);
        my_exit(-1);
    }
    fseek(fp,0,SEEK_END);
    long file_size=ftell(fp);
    fseek(fp,0,SEEK_SET);
    if (file_size > 8192)
    {
        fprintf(stderr,"json file is larger than the buffer size.\n");
        my_exit(-1);
    }
    
    fread(buffer,8192,1,fp);
    fclose(fp);

    parsed_json=json_tokener_parse(buffer);
    if (parsed_json == NULL)    
    {
        fprintf(stderr,"Error parsing json file: %s. Check for missing commas.\n",json_run_filename);
        my_exit(-1);  
    }

    get_binary_json_filename(parsed_json,rd);
    get_mode(parsed_json,rd);
    get_timeit(parsed_json,rd);
    get_display_disassembly(parsed_json,rd);
    if (rd->run_mode == eFAULT_rm)
    {
        get_output_directory_name(parsed_json,rd);
        get_threads(parsed_json,rd);
        get_fault_model_filename(parsed_json,rd);
        get_checkpoints(parsed_json,rd);
        get_max_instructions(parsed_json,rd);
        get_equivalents(parsed_json,rd);

        rd->total_num_checkpoints=0;
        if (rd->start_from_checkpoint == true)
        {
            get_num_checkpoints(parsed_json,rd);
        }
    }

}
