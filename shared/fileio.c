#include <unicorn/unicorn.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>
#include <json-c/json.h>
#include <time.h>
#include <assert.h>
#include "structs.h"
#include "run.h"
#include "utils.h"
#include "configuration.h"
#include "unicorn_engine.h"
#include "unicorn_consts.h"

void print_equivalence_list(current_run_state_t *current_run_state, uint64_t instruction)
{
    fprintf(current_run_state->file_fprintf, "****** Equivalence faults for instruction: %llu ******\n", instruction);
    for (uint64_t i = 0; i < current_run_state->equivalence_count; i++)
    {
        if (current_run_state->equivalences[i].fault_count > 1)
        {
            for (uint64_t j = 0; j < current_run_state->equivalences[i].fault_count; j++)
            {
                if (j == 0)
                {
                    fprintf(current_run_state->file_fprintf, "=Equivalence=\n");
                }
                fprintf(current_run_state->file_fprintf, "\t == =\t");
                print_fault_rule(current_run_state->file_fprintf, &current_run_state->equivalences[i].faults[j]);
            }
        }
    }
    fprintf(current_run_state->file_fprintf, "\n");
}

size_t context_size(uc_context *c)
{
    struct uc_context_copy
    {
        size_t size;
        char data[0];
    };

    struct uc_context_copy *context_copy = (struct uc_context_copy *)c;
    return context_copy->size;
}

void save_context_to_file(uc_engine *uc, uc_context* c, const char *filename)
{
    struct uc_context_copy
    {
        size_t size;
        char data[0];
    };

    struct uc_context_copy *context_copy = (struct uc_context_copy *)c;

    FILE *fp = fopen(filename, "wb");
    fwrite(context_copy, context_copy->size, 1, fp);
    fclose(fp);
}


void save_current_context_to_file(uc_engine *uc, const char *filename)
{
    struct uc_context_copy
    {
        size_t size;
        char data[0];
    };

    uc_context *c;
    uc_err err;

    err = uc_context_alloc(uc, &c);
    if (err != UC_ERR_OK)
    {
        fprintf(stderr, "Unable to allocate space for the context %u: %s\n", err, uc_strerror(err));
        my_exit(-1);
    }

    err = uc_context_save(uc, c);
    if (err != UC_ERR_OK)
    {
        fprintf(stderr, "Unable to save the context %u: %s\n", err, uc_strerror(err));
        my_exit(-1);
    }
    struct uc_context_copy *context_copy = (struct uc_context_copy *)c;

    FILE *fp = fopen(filename, "wb");
    fwrite(context_copy, context_copy->size, 1, fp);
    fclose(fp);
    uc_context_free(c);
}

void save_stack_to_file(uc_engine *uc, const char *filename)
{
    // Yes this is freed!
    uint8_t *my_bytes = MY_STACK_ALLOC(binary_file_details->stack.size);
    uc_err err = uc_mem_read(uc, binary_file_details->stack.address, my_bytes, binary_file_details->stack.size);
    if (err != UC_ERR_OK)
    {
        fprintf(stderr, "Unable to read the memory %u: %s\n", err, uc_strerror(err));
        my_exit(-1);
    }
    FILE *fp = fopen(filename, "wb");
    fwrite(my_bytes, binary_file_details->stack.size, 1, fp);
    fclose(fp);
}

void save_memory_to_file(uc_engine *uc, const char *filename, current_run_state_t *current_run_state)
{
    uint8_t *my_bytes = MY_STACK_ALLOC(binary_file_details->memory_main.size);
    uc_err err = uc_mem_read(uc, binary_file_details->memory_main.address, my_bytes, binary_file_details->memory_main.size);
    if (err != UC_ERR_OK)
    {
        fprintf(stderr, "Unable to read the memory %u: %s\n", err, uc_strerror(err));
        my_exit(-1);
    }
    FILE *fp = fopen(filename, "wb");
    fwrite(my_bytes, binary_file_details->memory_main.size, 1, fp);
    fclose(fp);
}

const char *skip_past(const char *lineptr, char c)
{
    while (*lineptr != c && *lineptr != '\0')
    {
        lineptr++;
    }
    if (*lineptr == c)
    {
        lineptr++;
        return lineptr;
    }
    return NULL;
}

void get_instructions_from_line(const char *original_line, instruction_range_fault_t *instruction_range_fault)
{
    if (strlen(original_line) < 3)
    {
        fprintf(stderr, "There was a problem with the instruction range. No valid range found.\n");
        my_exit(-1);
    }
    char *line = MY_STACK_ALLOC(strlen(original_line) + 1);
    // need a copy because strtok modifies the line
    strcpy(line, original_line);
    char *token = strtok(line, "-");
    if (token == NULL)
    {
        fprintf(stderr, "There was a problem with the instruction range. No range found.\n");
        my_exit(-1);
    }
    uint64_t start = atoi(token);

    token = strtok(NULL, "-");
    if (token == NULL)
    {
        fprintf(stderr, "There was a problem with the instruction range. No range found.\n");
        my_exit(-1);
    }
    uint64_t end = atoi(token);
    if (end < start)
    {
        fprintf(stderr, "There was a problem with the instruction range\n");
        my_exit(-1);
    }

    instruction_range_fault->instruction_start = start;
    instruction_range_fault->instruction_end = end;
}

uint64_t get_masks_from_line(const char *original_line, uint64_t **masks)
{
    char *line = MY_STACK_ALLOC(strlen(original_line) + 1);
    strcpy(line, original_line);
    uint64_t counter = 0;
    const char *comma = ",";
    const char *shift_symbol = "<";

    char *comma_state = NULL;
    char *comma_token = strtok_r(line, comma, &comma_state);
    uint64_t *my_vals = my_malloc(sizeof(uint64_t), "masks");

    while (comma_token != NULL)
    {
        char *shift_state = NULL;
        const char *shift_token = strtok_r(comma_token, shift_symbol, &shift_state);
        const char *mask_string = NULL;
        const char *shift_start_string = NULL;
        const char *shift_end_string = NULL;
        uint64_t mask_int, shift_start_int, shift_end_int;

        while (shift_token != NULL)
        {
            if (mask_string == NULL)
            {
                mask_string = shift_token;
                mask_int = strtol(mask_string, NULL, 16);
            }
            else if (shift_start_string == NULL)
            {
                shift_start_string = shift_token;
                shift_start_int = strtol(shift_start_string, NULL, 10);
            }
            else if (shift_end_string == NULL)
            {
                shift_end_string = shift_token;
                shift_end_int = strtol(shift_end_string, NULL, 10);
            }

            shift_token = strtok_r(NULL, shift_symbol, &shift_state);
        }

        // if only mask value - set the mask
        if (mask_string)
        {
            if (shift_start_string == NULL)
            {
                shift_start_int = 0;
            }
            if (shift_end_string == NULL)
            {
                shift_end_int = shift_start_int + 1;
            }

            for (uint64_t i = shift_start_int; i < shift_end_int; i++)
            {
                // malloc the space and save the mask
                my_vals = my_realloc(my_vals, (sizeof(uint64_t)) * (counter + 1), "masks");
                my_vals[counter] = mask_int << i;
                counter++;
            }
        }

        comma_token = strtok_r(NULL, comma, &comma_state);
    }
    *masks = my_vals;
    return counter;
}

uint128_t get_registers_from_line(const char *original_line)
{
    char *line = MY_STACK_ALLOC(strlen(original_line) + 1);
    uint128_t registers = 0;
    // need a copy because strtok modifies the line
    strcpy(line, original_line);
    char *token = strtok(line, ",");
    while (token != NULL)
    {
        trim(token);
        uint64_t temp = register_int_from_name(token);
        if (temp < 0 || temp > MAX_REGISTERS)
        {
            fprintf(stderr, "Register read from file outside the range of 0-%i.\n", MAX_REGISTERS);
            fprintf(stderr, "Register not found: %s\n", token);
            my_exit(-1);
        }
        set_bit(&registers, temp);
        token = strtok(NULL, ",");
    }
    return registers;
}


op_t get_operation_from_line(const char *original_line)
{
    char *line = MY_STACK_ALLOC(strlen(original_line) + 1);
    // need a copy because strtok modifies the line
    strcpy(line, original_line);
    trim(line);
    return (string_to_operation(line));
}

void get_opcode_filter_fault_from_line(const char *original_line, char **str)
{
    char *line = MY_STACK_ALLOC(strlen(original_line) + 1);
    // need a copy because strtok modifies the line
    strcpy(line, original_line);
    trim(line);

    int len = strlen(line);
    *str = my_malloc((len + 1) * sizeof(char), "opcode_filter_fault_text");
    memcpy(*str, line, len + 1);
}

void get_lifespan_fault_from_line(const char *original_line, lifespan_t *lifespan)
{
    char *line = MY_STACK_ALLOC(strlen(original_line) + 1);

    // need a copy because strtok modifies the line
    strcpy(line, original_line);

    // first one is value
    char *value = strtok(line, ",");
    uint64_t temp = atoi(value);
    lifespan->count = temp;
    lifespan->mode = eNONE_lsm;

    // second one is repeat or revert
    char *mode = strtok(NULL, ",");
    if (lifespan->count > 0 && !mode)
    {
        fprintf(stderr, "If lifespan > 0 you must have a mode. Options are: 'revert' or 'repeat': %s.\n", mode);
        my_exit(-1);
    }
    if (mode)
    {
        trim(mode);
        if (strncmp(mode, "revert", 6) == 0)
        {
            lifespan->mode = eREVERT_lsm;
        }
        else if (strncmp(mode, "repeat", 6) == 0)
        {
            lifespan->mode = eREPEAT_lsm;
        }
        else
        {
            fprintf(stderr, "Unable to open find lifespan mode. Options are: 'revert' or 'repeat': %s.\n", mode);
            my_exit(-1);
        }
    }
}

run_list_t *parse(const char *filename)
{
    FILE *fp = fopen(filename, "r");
    if (fp == NULL)
    {
        fprintf(stderr, "Unable to open rules file: %s.\n", filename);
        my_exit(-1);
    }

    /* HIERARCHY:
        INSTRUCTION_FAULT
            FAULT_TARGET (registers, IP)
                OP_CODE_FILTER (e.g. imul)
                    LIFESPAN
                        OPERATION FAULT (e.g XOR 0xFF)  */

    // Pre-allocate a 2k line buffer to prevent memory fragmentation. getLine() will realloc if it's too small.
    size_t line_len = 4096;
    char *lineptr = MY_STACK_ALLOC(line_len);
    size_t num_chars_read;

    run_list_t *run_list = (run_list_t *)my_malloc(sizeof(run_list_t), "run_list");
    instruction_range_fault_t *current_instruction_range_fault = NULL;
    target_fault_t *current_target_fault = NULL;
    opcode_filter_fault_t *current_opcode_filter_fault = NULL;
    lifespan_fault_t *current_lifespan_fault = NULL;
    operation_fault_t *current_operation_fault = NULL;

    while ((num_chars_read = getline(&lineptr, &line_len, fp)) != -1)
    {
        // Trim leading space
        const char *line = lineptr;
        while (isspace(*line))
        {
            line++;
        }

        if (strlen(line) > 0 && line[0] != '#')
        {
            if (strncmp(line, "Instructions:", 13) == 0)
            {
                // This is the instruction lines (which lines to fault)
                instruction_range_fault_t *new_instruction_range_fault = (instruction_range_fault_t *)my_malloc(sizeof(instruction_range_fault_t), "instruction_range_fault");
                memset(new_instruction_range_fault, 0, sizeof(instruction_range_fault_t));

                const char *instruction_values = skip_past(line, ':');
                if (instruction_values == NULL)
                {
                    fprintf(stderr, "Parsing fault file. No instruction_values found - please check the format of your file.\n");
                    my_exit(-1);
                }
                get_instructions_from_line(instruction_values, new_instruction_range_fault);

                if (current_instruction_range_fault != NULL)
                {
                    // Attach us to the end of the chain
                    current_instruction_range_fault->next = new_instruction_range_fault;
                }
                else
                {
                    // This is the first instruction_range_fault, set us as the head.
                    run_list->instruction_range_fault = new_instruction_range_fault;
                }
                current_instruction_range_fault = new_instruction_range_fault;
                current_target_fault = NULL;
            }
            else if ((strncmp(line, "Registers:", 10) == 0) || (strncmp(line, "Registers-force:", 15) == 0) || (strncmp(line, "Instruction:", 11) == 0) || (strncmp(line, "Flags:", 6) == 0) || (strncmp(line, "Instruction Pointer:", 20) == 0))
            {
                if (current_instruction_range_fault == NULL)
                {
                    fprintf(stderr, "Found 'Registers' or 'Flags' or 'Instruction Pointer' or outside of an instruction block.\n");
                    my_exit(-1);
                }

                target_fault_t *new_target_fault = (target_fault_t *)my_malloc(sizeof(target_fault_t), "target_fault");
                memset(new_target_fault, 0, sizeof(target_fault_t));

                const char *objects = skip_past(line, ':');
                if (objects == NULL)
                {
                    fprintf(stderr, "Parsing fault file. No registers/Intruction Pointer found - please check the format of your file.\n\n\n");
                    my_exit(-1);
                }

                // new register - so reset Op code fault - need a new list for a new set of registers
                current_opcode_filter_fault = NULL;


                if ((strncmp(line, "Registers", 9) == 0))
                {
                    new_target_fault->target = reg_ft; // REGISTERS
                    new_target_fault->register_bit = get_registers_from_line(objects);
                    new_target_fault->force = false;
                    if ((strncmp(line, "Registers-force", 15) == 0))
                    {
                        new_target_fault->force = true;
                    }
                }
                else if ((strncmp(line, "Instruction Pointer", 19) == 0))
                {
                    new_target_fault->target = instruction_pointer_ft; // IP
                    new_target_fault->register_bit = 0;        // This isn't relevant for the instruction pointer
                }
                else if ((strncmp(line, "Instruction", 11) == 0))
                {
                    new_target_fault->target = instruction_ft;  // Instruction
                    new_target_fault->register_bit = 0; // This isn't relevant for the instruction
                }
                else
                {
                    fprintf(stderr, "Unable to find an object (register/instruction/instruction pointer)\n");
                    my_exit(-1);
                }
                if (current_target_fault != NULL)
                {
                    // Attach this object (registers) to the end
                    current_target_fault->next = new_target_fault;
                }
                else
                {
                    // This is the first target_fault (registers ), set us as the head.
                    current_instruction_range_fault->target_fault_head = new_target_fault;
                }
                // move the current target_fault to the new one we just made
                current_target_fault = new_target_fault;
            }
            else if (strncmp(line, "Op_codes", 7) == 0)
            {
                current_lifespan_fault = NULL;

                if (current_target_fault == NULL)
                {
                    fprintf(stderr, "Found 'Op_codes' outside of a target_fault ('Registers', 'Instructions', 'Instruction Pointer') block.\n");
                    fprintf(stderr, "Line found: %s\n", line);
                    my_exit(-1);
                }

                opcode_filter_fault_t *new_opcode_string_list = (opcode_filter_fault_t *)my_malloc(sizeof(opcode_filter_fault_t), "opcode_filter_fault");
                memset(new_opcode_string_list, 0, sizeof(opcode_filter_fault_t));
                const char *opcode_filter_fault_string = skip_past(line, ':');

                if (opcode_filter_fault_string == NULL)
                {
                    fprintf(stderr, "Parsing fault file. No opcodes string found - please check the format of your file. (Hint, use: ALL if you don't want to filter opcodes).\n");
                    my_exit(-1);
                }

                // populate the list of opcode_filter_faults
                get_opcode_filter_fault_from_line(opcode_filter_fault_string, &new_opcode_string_list->string);

                if (new_opcode_string_list->string == NULL)
                {
                    fprintf(stderr, "Parsing fault file. No valid opcode found - please check the format of your file.\n");
                    my_exit(-1);
                }

                if (strncmp(new_opcode_string_list->string, "ALL", 3) == 0)
                {
                    my_free(new_opcode_string_list->string, "opcode_filter_fault_text");
                    new_opcode_string_list->string = NULL;
                }
                if (current_opcode_filter_fault != NULL)
                {
                    // Attach us to the end of the chain
                    current_opcode_filter_fault->next = new_opcode_string_list;
                }
                else
                {
                    // This is the first operation_list, set us as the head.
                    current_target_fault->opcode_filter_fault_head = new_opcode_string_list;
                }
                current_opcode_filter_fault = new_opcode_string_list;
            }
            else if (strncmp(line, "Lifespan", 8) == 0)
            {
                current_operation_fault = NULL;

                if (current_opcode_filter_fault == NULL)
                {
                    fprintf(stderr, "Found 'Lifespan' outside of a opcode filter block.\n");
                    printf("Line: %s \n", line);
                    my_exit(-1);
                }

                lifespan_fault_t *new_lifespan_fault_list = (lifespan_fault_t *)my_malloc(sizeof(lifespan_fault_t), "lifespan_fault_list");
                memset(new_lifespan_fault_list, 0, sizeof(lifespan_fault_t));
                const char *lifespan_fault_string = skip_past(line, ':');

                if (lifespan_fault_string == NULL)
                {
                    fprintf(stderr, "Parsing fault file. No valid lifespan value found - please check the format of your file..\n");
                    my_exit(-1);
                }
                get_lifespan_fault_from_line(lifespan_fault_string, &new_lifespan_fault_list->lifespan);

                if (current_lifespan_fault != NULL)
                {
                    // Attach us to the end of the chain
                    current_lifespan_fault->next = new_lifespan_fault_list;
                }
                else
                {
                    // This is the first lifespan list, set us as the head in the parent thing.
                    current_opcode_filter_fault->lifespan_head = new_lifespan_fault_list;
                }
                current_lifespan_fault = new_lifespan_fault_list;
            }
            else if (strncmp(line, "Operation", 9) == 0)
            {
                if (current_lifespan_fault == NULL)
                {
                    fprintf(stderr, "Found 'Operation' outside of Lifespan block.\n");
                    printf("Line: %s \n", line);
                    my_exit(-1);
                }

                operation_fault_t *new_operation_list = (operation_fault_t *)my_malloc(sizeof(operation_fault_t), "operation_list");
                memset(new_operation_list, 0, sizeof(operation_fault_t));
                const char *operation_masks = skip_past(line, ':');
                if (operation_masks == NULL)
                {
                    fprintf(stderr, "Parsing fault file. No operations found - please check the format of your file.\n");
                    my_exit(-1);
                }
                // populate the list of operations here:
                new_operation_list->operation = get_operation_from_line(operation_masks);
                if (new_operation_list->operation == eNOT_eSET_op)
                {
                    fprintf(stderr, "No valid operation found - please check the format of your file.\n");
                    fprintf(stderr, "Operation:.%s.\n", operation_masks);
                    my_exit(-1);
                }

                if (current_operation_fault != NULL)
                {
                    // Attach us to the end of the chain
                    current_operation_fault->next = new_operation_list;
                }
                else
                {
                    // This is the first operation_list, set us as the head.
                    current_lifespan_fault->operation_fault_head = new_operation_list;
                }
                current_operation_fault = new_operation_list;
            }
            else if (strncmp(line, "Masks:", 6) == 0)
            {
                if (current_operation_fault == NULL)
                {
                    fprintf(stderr, "Parsing fault file. Masks found - but no Lifespan to go with the mask.\n> %s\n", line);
                    my_exit(-1);
                }

                const char *mask_masks = skip_past(line, ':');
                if (mask_masks == NULL)
                {
                    fprintf(stderr, "Parsing fault file. No mask masks found - please check the format of your file.\n");
                    my_exit(-1);
                }
                current_operation_fault->mask_count = get_masks_from_line(mask_masks, &(current_operation_fault->masks));
            }
        }
    }
    return run_list;
}

void print_run_list(const run_list_t *run_list)
{
    FILE *f = stdout;
    fprintf(f, "\n~~~ FAULTS TO EMULATE  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");

    instruction_range_fault_t *current_instruction_range_fault = run_list->instruction_range_fault;
    while (current_instruction_range_fault != NULL)
    {
        // FAULTS
        fprintf(f, "Fault: %llu-%llu\n", current_instruction_range_fault->instruction_start, current_instruction_range_fault->instruction_end);

        target_fault_t *current_target_fault = current_instruction_range_fault->target_fault_head;
        while (current_target_fault != NULL)
        {
            if (current_target_fault->target == reg_ft)
            {
                // REGISTERS
                fprintf(f, "  Registers%s: ", current_target_fault->force == 1 ? " [FORCE FAULT]" : "");

                for (int reg_num = 0; reg_num < MAX_REGISTERS; reg_num++)
                {
                    if (is_bit_set(current_target_fault->register_bit, reg_num))
                    {
                        fprintf(f, "%s ", register_name_from_int(reg_num));
                    }
                }
            }
            else if (current_target_fault->target == instruction_pointer_ft)
            {
                fprintf(f, "  Instruction Pointer ");
            }
            else if (current_target_fault->target == instruction_ft)
            {
                fprintf(f, "  Instruction ");
            }
            else
            {
                fprintf(stderr, "Unable to find an object (register/code/instruction pointer)\n");
                my_exit(-1);
            }
            fprintf(f, "\n");

            opcode_filter_fault_t *current_opcode_filter_fault = current_target_fault->opcode_filter_fault_head;
            while (current_opcode_filter_fault != NULL)
            {
                fprintf(f, "    Opcode filter: %s \n", current_opcode_filter_fault->string == NULL ? "ALL" : current_opcode_filter_fault->string);
                lifespan_fault_t *current_lifespan_fault = current_opcode_filter_fault->lifespan_head;
                while (current_lifespan_fault != NULL)
                {
                    // FAULT LIFECYCLE
                    fprintf(f, "\tLifespan: %llu ", current_lifespan_fault->lifespan.count);
                    if (current_lifespan_fault->lifespan.count > 0)
                    {
                        fprintf(f, "Mode: %s", lifespan_mode_to_string(current_lifespan_fault->lifespan.mode));
                    }
                    fprintf(f, "\n");

                    operation_fault_t *current_operation = current_lifespan_fault->operation_fault_head;
                    while (current_operation != NULL)
                    {
                        // OPERATIONS
                        fprintf(f, "\t  %s operation. \n", operation_to_string(current_operation->operation));
                        // MASKS
                        fprintf(f, "\t\t");
                        for (uint64_t temp_num = 0; temp_num < current_operation->mask_count; temp_num++)
                        {
                            fprintf(f, "0x%08llx ", current_operation->masks[temp_num]);
                        }
                        fprintf(f, "\n");
                        current_operation = current_operation->next;
                    }
                    current_lifespan_fault = current_lifespan_fault->next;
                }
                current_opcode_filter_fault = current_opcode_filter_fault->next;
            }
            current_target_fault = current_target_fault->next;
        }
        current_instruction_range_fault = current_instruction_range_fault->next;
    }
}
