#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include <unicorn/unicorn.h>
#include "utils.h"
#include "unicorn_engine.h"
#include "configuration.h"
#include "unicorn_consts.h"

uc_err _uc_err_check(uc_err err, const char* expr)
{
    if (err) 
    {
        fprintf(stderr, "Failed on %s with error: %s\n", expr, uc_strerror(err)); my_exit(1);
    }
    return err;
}
/*super hash function by Paul Hsieh*/
uint32_t super_fast_hash (const uint8_t * data, int len) 
{
    uint32_t hash=len, tmp;
    int rem;

        if (len <=0 || data == NULL) return 0;

        rem=len & 3;
        len >>=2;

        /* Main loop */
        for (;len > 0; len--) {
            hash  +=get16bits (data);
            tmp   =(get16bits (data+2) << 11) ^ hash;
            hash  =(hash << 16) ^ tmp;
            data  +=2*sizeof (uint16_t);
            hash  +=hash >> 11;
        }

        /* Handle end cases */
        switch (rem) {
            case 3: hash +=get16bits (data);
                    hash ^=hash << 16;
                    hash ^=((signed char)data[sizeof (uint16_t)]) << 18;
                    hash +=hash >> 11;
                    break;
            case 2: hash +=get16bits (data);
                    hash ^=hash << 11;
                    hash +=hash >> 17;
                    break;
            case 1: hash +=(signed char)*data;
                    hash ^=hash << 10;
                    hash +=hash >> 1;
        }

        /* Force "avalanching" of final 127 bits */
        hash ^=hash << 3;
        hash +=hash >> 5;
        hash ^=hash << 4;
        hash +=hash >> 17;
        hash ^=hash << 25;
        hash +=hash >> 6;

        return hash;
}

void print_memory_and_stack (line_details_t* line_details_array, uint64_t num)
{
    uint64_t i;
    printf("\n~~~ Printing stack. Size: %llu ~~~\n",binary_file_details->stack.size);
    for (i=0;i<binary_file_details->stack.size;i++)
    {
        printf("0x%08" PRIx64":",i);
        printf("%" PRIx8 " ",line_details_array[num].stack[i]);
        printf("\n");
    }

    printf("\n~~~ Printing memory main. Size: %llu ~~~\n",binary_file_details->memory_main.size);
    for (i=0;i<binary_file_details->memory_main.size;i++)
    {
        printf("%" PRIx8 " ",line_details_array[num].memory_main[i]);
    }

    printf("\n~~~ Printing memory other ~~~");
    for (int j=0;j<binary_file_details->memory_other_count;j++)
    {
        printf("\n~~~ Printing memory other Number: %i. Size: %llu  ~~~\n",j,binary_file_details->memory_other[j].size);

        for (i=0;i<binary_file_details->memory_other[j].size;i++)
        {
            printf("%" PRIx8 " ",line_details_array[num].memory_other[j][i]);
        }
    }
    printf ("\n");
}


static int malloc_counter=0;
static int free_counter=0;
static int mem_counter=0;
void my_malloc_free_print()
{
  return;
  //printf("malloc: %i. free: %i. \n",malloc_counter,free_counter);
}
void *my_realloc (void* ptrptr, size_t s, char* description)
{
    mem_counter++;
    if (ptrptr == NULL)
    {
            malloc_counter++;
    }
    void* ptr=realloc(ptrptr, s);
    if (ptr == NULL)
    {
        fprintf(stderr, "realloc failed for %s.\n",description);
        my_exit(-1);
    }

    #ifdef SHOW_MALLOC
        if (ptrptr == NULL || ptrptr != ptr)
        {
            printf_debug("Description: %s. Pointer: %p. %05i. 2. MY_REALLOC.  Previous pointer: %p. Size: %ld\n",description,ptr,mem_counter,ptrptr,s);
        }
    #endif

    return ptr;
}

void *my_malloc (size_t s, char* description)
{
    mem_counter++;
    void* ptr=malloc(s);
    if (ptr == NULL)
    {
        fprintf(stderr, "malloc failed for %s.\n",description);
        my_exit(-1);
    }
    malloc_counter++;
    #ifdef SHOW_MALLOC
        printf_debug("Description: %s. Pointer: %p. %05i. 1. MY_MALLOC.  Size: %ld (0x%" PRIx64 ")\n",description,ptr,mem_counter,s,s);    
        #endif
    return ptr;
}

void my_exit(int exit_value)
{
    exit(exit_value);
}

void my_free (void* ptr, char* description)
{
    if (ptr != NULL)
    {
        mem_counter++;
        #ifdef SHOW_MALLOC
            printf_debug("Description: %s. Pointer: %p. %05i. 3. MY_FREE.    \n",description,ptr,mem_counter);
        #endif
    
        free(ptr);
        free_counter++;
    }
}

void print_current_run_state(current_run_state_t* c)
{
    printf("Directory for output:        %s\n",c->directory);
    printf("Run mode:                    %s\n",run_mode_to_string(c->run_mode));
    printf("Run state:                   %s\n",run_state_to_string(c->run_state));
    printf("Instruction count:           %llu\n",c->instruction_count);
    printf("Total instruction count:     %llu\n",c->total_instruction_count);
    printf("Number of checkpoints:       %llu\n",c->total_num_checkpoints);
    printf("Last address:                0x%" PRIx64 "\n",c->last_address);
    printf("In fault range:              %s\n",c->in_fault_range == 1? "Yes": "No");
    printf("Fault rule - set             %s\n",c->fault_rule.set == 1? "Yes": "No");
    printf("Start from checkpoint:       %s\n",c->start_from_checkpoint == 1? "Yes": "No");
    printf("Stop on equivalence:         %s\n",c->stop_on_equivalence == 1? "Yes": "No");
    printf("Time to run:                 %llu\n",c->time_to_run);
    printf("Time to restore checkpoint:  %llu\n",c->time_to_restore_checkpoint);
    printf("Equivalence count:           %llu\n",c->equivalence_count);
    printf("Checkpoints: \n");
    for (uint64_t i=1 ; i<c->total_instruction_count+1;i++)
    {
        if (c->line_details_array[i].checkpoint == true)
        {
            printf(" > Instruction: %08lli Address: 0x%" PRIx64 " Hitcount: %lli\n",
            i, c->line_details_array[i].address, c->line_details_array[i].hit_count);
        }
    }
}

uint64_t thumb_check_address(uint64_t a)
{
    if (binary_file_details->my_uc_arch != UC_ARCH_ARM  && binary_file_details->my_uc_arch != UC_ARCH_ARM64)   
    {
        return a;
    }
    else if (a&1)
    {
        return --a;
    }
    else
    {
        return a;
    }
}

void print_fault_rule_no_newline( FILE *fd,fault_rule_t *fault_rule)
{
    fprintf(fd,"Instruction: %08lli. Faulting Target: ",fault_rule->instruction);
    switch (fault_rule->target)
    {
        case reg_ft:
            fprintf(fd,"Register%s. Reg#: %s. Mask: 0x%016llx. ",
                fault_rule->force == true?" [FORCE FAULT]":"", 
                register_name_from_int(fault_rule->number),
                fault_rule->mask);
            break;
        case instruction_pointer_ft:
            fprintf(fd,"InstructionPointer. \t\t");
            break;
        case instruction_ft:
            fprintf(fd,"Instruction. Mask: 0x%016llx. ",fault_rule->mask);
            break;
        default:
            fprintf(stderr, "No valid target specified unable to print fault fule.\n");
            my_exit(-1);
    }           
    fprintf(fd,"Operation: %s. ", operation_to_string(fault_rule->operation));
}

void print_fault_rule( FILE *fd,fault_rule_t *fault_rule)
{
    print_fault_rule_no_newline(fd,fault_rule);
    fprintf(fd,"\n");
        
}

void print_fault_rule_with_address( FILE *fd,fault_rule_t *fault_rule)
{
    fprintf(fd,"Address 0x%08llx. ", fault_rule->faulted_address);
    print_fault_rule_no_newline(fd,fault_rule);
}


void print_register(uc_engine* uc,FILE* fd,uint64_t reg)
{
    uint64_t r=0;
    uc_reg_read(uc, uc_reg_from_int(reg), &r);
    fprintf(fd,"%s=0x%" PRIx64 "\n",register_name_from_int(reg), r);
}

void print_register_from_name(uc_engine* uc,FILE* fd,char* reg_name)
{
    uint64_t r=0;
    uint64_t reg=register_int_from_name(reg_name);
    uc_reg_read(uc, uc_reg_from_int(reg), &r);
    fprintf(fd,"%s=0x%" PRIx64 "\n",reg_name, r);
}

void print_all_registers(uc_engine* uc,FILE* fd)
{
    for (uint64_t i=0;i<MAX_REGISTERS;i++)
    {
        print_register(uc,fd,i);
    }
}

void print_register_bitmap(uint128_t bitmap)
{
    //will need fixing for 128
    uint64_t bottom_bits = (uint64_t)bitmap;
    uint64_t top_bits = (uint64_t)(bitmap>>64);
    printf(" %s%s",decimal_to_binary(top_bits),decimal_to_binary(bottom_bits));
}

void print_memory(uc_engine* uc, FILE* fd)
{
    uint8_t* all_memory=MY_STACK_ALLOC(sizeof(uint8_t)*binary_file_details->memory_main.size);
    uc_mem_read(uc,binary_file_details->memory_main.address,all_memory,binary_file_details->memory_main.size);
    printf("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Memory. Address start: 0x%08llx address size:0x%08llx~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n",
    binary_file_details->memory_main.address,binary_file_details->memory_main.size );
    for (uint64_t i=0;i<binary_file_details->memory_main.size; i+=8)
    {
        printf ("0x%08llx\t",binary_file_details->memory_main.address+i);
        phex(fd,all_memory+i,8);
    }
}

uint64_t address_hit(address_hit_counter_t* a,uint64_t address)
{
    /* yes - I am aware this is horrible and hacking and won't be linear! */
    uint64_t address_index=(address-a->min_address)/(a->mod_address);
    a->counter[address_index]++;
    return a->counter[address_index];
}

void print_stack(uc_engine* uc, FILE* fd)
{
    uint8_t* all_stack=MY_STACK_ALLOC(sizeof(uint8_t)*binary_file_details->stack.size);
    uc_mem_read(uc,binary_file_details->stack.address,all_stack,binary_file_details->stack.size);
    fprintf(fd,"\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Stack. Address start: 0x%08llx address size:0x%08llx~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n",
    binary_file_details->stack.address,binary_file_details->stack.size );
    for (uint64_t i=0;i<binary_file_details->stack.size; i+=8)
    {   
        fprintf (fd,"0x%08llx\t",binary_file_details->stack.address+i);
        phex(fd,all_stack+i,8);
    }
}

void print_stack_from_sp(uc_engine* uc, FILE* fd, uint64_t stack_size_to_print)
{
    uint8_t* stack=MY_STACK_ALLOC(sizeof(uint8_t) * stack_size_to_print);
    const int steps=4;
    uint64_t sp_address=0;

    // Read stack address
    uc_err err = uc_reg_read(uc, binary_file_details->my_sp_reg,&sp_address);
    if (err) 
    {
        fprintf(stderr, "Failed in print stack reading the sp register with error: %s\n", uc_strerror(err)); 
        my_exit(1);
    }


    if ((sp_address + stack_size_to_print) > (binary_file_details->stack.address + binary_file_details->stack.size))
        {
            fprintf(fd, "Stack addresses are 0x%" PRIx64" - 0x%" PRIx64 "\n",binary_file_details->stack.address, binary_file_details->stack.address+binary_file_details->stack.size);
            fprintf(fd, "Attempting to read outside of allocated stack address space: sp_address: 0x%" PRIx64 " and size: 0x%" PRIx64 "\n",sp_address,stack_size_to_print);

            stack_size_to_print=(binary_file_details->stack.address + binary_file_details->stack.size)-sp_address;
            fprintf(fd, "Changing size to: 0x%llx\n", stack_size_to_print);
        }

     if (stack_size_to_print<=0)
    {
        return;
    }

    err=uc_mem_read(uc,sp_address,stack,stack_size_to_print);
    if (err) 
    {
        fprintf(stderr, "Failed in print stack reading the data from the stack. Stack address: 0x%" PRIx64 ". Stack size to read: %llx. Error: %s\n", 
            sp_address,
            stack_size_to_print,
            uc_strerror(err)); 
        my_exit(1);
    }
    fprintf(fd,"\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Stack:  Address start: 0x%08llx address size:0x%08llx~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n", sp_address,stack_size_to_print );

    for (uint64_t i=0;i<stack_size_to_print; i+=steps)
    {   
        fprintf (fd,"0x%08llx\t",sp_address+i);
        phex(fd,stack+i,steps);
        //phex_reverse(fd,stack+i,steps);
    }
    fprintf(fd,"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
}

const char* human_size (uint128_t bytes)
{
	char *suffix[]={"B", "KB", "MB", "GB", "TB"};
	char length=sizeof(suffix) / sizeof(suffix[0]);

	int i=0;
	double dblBytes=bytes;

	if (bytes > 1024) 
    {
		for (i=0; (bytes / 1024) > 0 && i<length-1; i++, bytes /=1024)
			dblBytes=bytes / 1024.0;
	}

	static char output[30];
	sprintf(output, "%.02lf %s", dblBytes, suffix[i]);
	return output;
}

void print_binary2(FILE* f,uint64_t number)
{
    fprintf(f,"\n Value now: %" PRIx64 "",number);
    if (number >> 1) {
        print_binary2(f,number >> 1);
    }
    fprintf(f,"%i",(number & 1) ? '1' : '0');
}

const char* lifespan_mode_to_string (lifespan_mode  lsm)
{
    switch (lsm)
    {
        case eREVERT_lsm:
            return "revert";
        case eREPEAT_lsm:
            return "repeat";
        default:
            return "unknown";
    }
}
const char* run_state_to_string (run_state rs)
{
    switch (rs)
    {
        case NONE_rs:
            return "None";
        case STARTED_rs:
            return "reached start address";
        case STARTED_FROM_CHECKPOINT_rs:
            return "started from checkpoint";
        case FAULTED_rs:
            return "faulted";
        case EQUIVALENT_rs:
            return "equivalent";
        case TIMED_OUT_rs:
            return "timed out";
        case ERRORED_rs:
            return "errored";
        case INTERRUPT_rs:
            return "interrupted";
        case HARD_STOP_rs:
            return "hard stop";
        case END_ADDRESS_rs:
            return "end address";
        case END_ADDRESS_AND_FAULTED_rs:
            return "end address and faulted";
        case MAX_INSTRUCTIONS_REACHED_rs:
            return "max instructions reached";
        case INSTRUCTION_ERROR_rs:
            return "Instruction was unable to be disassembled";
        default:
            return "Not known";
    }
}  

const char* run_mode_to_string (run_mode rm)
{
    switch (rm)
    {
        case eNONE_rm:
            return "None";
        case eTEST_rm:
            return "test";
        case eGOLDEN_rm:
            return "run";
        case eGOLDENRUN_FULL_rm:
            return "golden run full";
        case eDEBUG_rm:
            return "debug";
        case eFAULT_rm:
            return "fault";
        case eSTATS_rm:
            return "stats";
        case eMEMHOOK_rm:
            return "memhook";
        case eCOUNT_INSTRUCTIONS_rm:
            return "counting instructions";
        case eTIMING_CHECKPOINT_rm:
            return "timing checkpoint";
        default:
            return "Not known";
    }
}
uint64_t fault_reg (uint64_t mask, op_t fault_op, uint64_t tmp,uint64_t size)
{
    switch (fault_op)
    {   
        case eAND_op:
            return tmp & mask;
        case eOR_op:
            return tmp|mask;
        case eXOR_op:
            return tmp^mask;
        case eADD_op:
            return tmp+mask;
        case eSKIP_op:
            return tmp+size;
        case eSET_op:
            return mask;
        default:
            fprintf (stderr, "Fault not known: %s - please check fault file.\n",operation_to_string(fault_op));
            my_exit(-1);
    }   
    return tmp;
}

void fault_instruction (uint64_t mask, op_t fault_op, uint8_t* in,uint8_t* out,uint64_t size, FILE* f)
{
    if ((mask >> (size*8)) > 1)
    {
        fprintf_output(f,"Warning - the Mask 0x%" PRIx64 " is larger than the instruction - so some bytes in the mask will be ingored\n",mask);
    }
    ///TODOTODO think about endianness - what if the mask is too small??
    for (uint64_t i=0;i<size;i++)
    {
        uint8_t mask_8bit=(mask>>(8*i))&0xFF;
        switch (fault_op)
        {   
            case eAND_op:
                out[i]=in[i] & mask_8bit;
                break;
            case eOR_op:
                out[i]=in[i] | mask_8bit;
                break;
            case eXOR_op:
                out[i]=in[i] ^ mask_8bit;
                break;
            case eADD_op:
                out[i]=in[i] + mask_8bit;
                break;
            case eSET_op:
                out[i]=mask_8bit;
                break;
            default:
                fprintf(stderr, "Operation %s is not valid for faulting the code.\n",operation_to_string(fault_op));
                my_exit(-1);
        }   
    }
}

uint64_t IP_fault_skip (op_t fault_op, uint64_t tmp,uint64_t size)
{
    switch (fault_op)
    {   
        case eSKIP_op:
            if (binary_file_details->my_uc_arch == UC_ARCH_ARM  || binary_file_details->my_uc_arch == UC_ARCH_ARM64)   
            {
            return tmp+size+1;
            }
            return tmp+size;
        default:
            fprintf(stderr, "Operation %s is not valid for faulting the instruction register. SKIP is the only valid instruction.\n",operation_to_string(fault_op));
            my_exit(-1);
    }   
    return tmp;
}

bool file_exists (const char * filename)
{
    FILE *file;
    file=fopen(filename, "r");
    if (file)
    {   
        fclose(file);
        return true;
    }   
    return false;
}

void phex(FILE* fd,uint8_t* str, uint64_t len)
{
    uint64_t i;
    for (i=0;i<len;i++)
    {
        fprintf(fd,"%.2x",str[i]);
    }
    fprintf(fd,"\n");
}

void sphex(uint8_t* str, uint64_t len,char* s)
{
    char two_chars[3];
    uint64_t i;
    for (i=0;i<len;i++)
    {
        sprintf(two_chars,"%.2x",str[i]);
        strcat(s,two_chars);
    }
    strcat(s,"\n");
}

void phex_reverse(FILE* fd,uint8_t* str, uint64_t len)
{
    uint64_t i;
    for (i=0;i<len;i++)
        fprintf(fd,"%.2x",str[len-i-1]);
    fprintf(fd,"\n");
}

void set_bit64(uint64_t* line_to_set, uint64_t bit_position)
{
    uint64_t one=1;
    *line_to_set = *line_to_set | (one << bit_position);
}

void set_bit(uint128_t* line_to_set, uint64_t bit_position)
{
    uint128_t one=1;
    *line_to_set = *line_to_set | (one << bit_position);
}

bool is_bit_set(uint128_t line_to_set, uint64_t bit_position)
{
    uint128_t one=1;
    return (line_to_set >> bit_position) & one;
}

int hex_string_to_byte_array (uint8_t* out_byte_array,const char *hex_string)
{ 
    size_t length=strlen(hex_string);
    assert(length % 2 == 0);
    length=length/ 2;
    for (size_t i=0, j=0;j < length; i+=2,j++)
    {   
        out_byte_array[j]=(hex_string[i]% 32 + 9) % 25 * 16 + (hex_string[i+1] % 32 +9) % 25; 
    }   
    return length;
}

/**
 * Remove leading and trailing white space characters
 */
void trim(char * str)
{
    int index, i;

    /*
     * Trim leading white spaces
     */
    index=0;
    while(str[index] == ' ' || str[index] == '\t' || str[index] == '\n'  || str[index] == '\r' || str[index] == 0)
    {
        index++;
    }

    /* Shift all trailing characters to its left */
    i=0;
    while(str[i + index] != '\0')
    {
        str[i]=str[i + index];
        i++;
    }
    str[i]='\0'; // Terminate string with NULL

    /*
     * Trim trailing white spaces
     */
    i=0;
    index=-1;
    while(str[i] != '\0')
    {
        if (str[i] != ' ' && str[i] != '\t' && str[i] != '\n'  && str[i] != '\r' && str[i] != 0)
        {
            index=i;
        }
        i++;
    }

    /* Mark the next character to last non white space character as NULL */
    str[index + 1]='\0';
}

op_t string_to_operation(char* operation_str)
{
    if (strcasecmp(operation_str,"AND") == 0)
        return eAND_op;
    if (strcasecmp(operation_str,"OR") == 0)
        return eOR_op;
    if (strcasecmp(operation_str,"XOR") == 0)
        return eXOR_op;
    if (strcasecmp(operation_str,"ADD") == 0)
        return eADD_op;
    if (strcasecmp(operation_str,"SKIP") == 0)
        return eSKIP_op;
    if (strcasecmp(operation_str,"SET") == 0)
        return eSET_op;
    if (strcasecmp(operation_str,"FLIP") == 0)
        return eFLIP_op;
    if (strcasecmp(operation_str,"CLEAR") == 0)
        return eCLEAR_op;
    return eNOT_eSET_op;
}

const char* operation_to_string(op_t operation_type)
{
    switch (operation_type)
    {
        case eAND_op:
            return "AND";
        case eOR_op:
            return "OR";
        case eXOR_op:
            return "XOR";
        case eADD_op:
            return "ADD";
        case eSKIP_op:
            return "SKIP";
        case eSET_op:
            return "SET";
        case eFLIP_op:
            return "FLIP";
        case eCLEAR_op:
            return "CLEAR";
        default:
            return "not_set";
    }   
    return "not_set";
}

const char* target_to_string(fault_target target)
{
    switch (target)
    {
        case reg_ft:
            return "Register";
        case instruction_pointer_ft:
            return "Instruction Pointer";
        case instruction_ft:
            return "Instruction";
        default:
            return "not_set";
    }   
    return "not_set";
}

//assumes little endian
void print_binary(size_t const size, void const * const ptr, FILE* fd)
{
    unsigned char *b=(unsigned char*) ptr;
    unsigned char byte;
    int i, j;

    for (i=size-1;i>=0;i--)
    {
        for (j=7;j>=0;j--)
        {
            byte=(b[i] >> j) & 1;
            fprintf(fd,"%u", byte);
        }
    }
    puts("");
}

char *decimal_to_binary(uint64_t n)
{
    int c, d, count;
    char *pointer;

    count=0;
    pointer=(char*)MY_STACK_ALLOC(64+1);

    if (pointer == NULL)
        my_exit(EXIT_FAILURE);
        
    for (c=63 ; c >=0 ; c--)
    {
        d=n >> c;
        
        if (d & 1)
            *(pointer+count)=1 + '0';
        else
            *(pointer+count)=0 + '0';
        
        count++;
    }
    *(pointer+count)='\0';

    return  pointer;
}

void print_binary_file_details()
{
    printf("Filename:                %s\n",    binary_file_details->binary_filename);
    printf("Unicorn arch:            %s (%i)\n",unicorn_arch_name_from_int(binary_file_details->my_uc_arch) ,binary_file_details->my_uc_arch);
    printf("Unicorn mode:            %s (%i)\n",unicorn_mode_name_from_int(binary_file_details->my_uc_mode) ,binary_file_details->my_uc_mode);
    printf("Capstone arch:           %s (%i)\n",capstone_arch_name_from_int(binary_file_details->my_cs_arch),binary_file_details->my_cs_arch);
    printf("Capstone mode:           %s (%i)\n",capstone_mode_name_from_int(binary_file_details->my_cs_mode),binary_file_details->my_cs_mode);
    printf("my_pc_reg:               %i\n",    binary_file_details->my_pc_reg);
    printf("my_sp_reg:               %i\n",    binary_file_details->my_sp_reg);
    printf("code offset:             0x%" PRIx64 "\n", binary_file_details->code_offset);
    printf("code_start_address:      0x%" PRIx64 "\n", binary_file_details->code_start_address);
    printf("code_end_address:        0x%" PRIx64 "\n", binary_file_details->code_end_address);
    printf("fault_start_address:     0x%" PRIx64 "\n", binary_file_details->fault_start_address);
    printf("fault_end_address:       0x%" PRIx64 "\n", binary_file_details->fault_end_address);
    printf("timeout:                 %llu\n",   binary_file_details->timeout);
    uint64_t i;
    for (i=0;i<binary_file_details->skips_count;i++)
    {
        printf("Skip address:            0x%" PRIx64 "\n",binary_file_details->skips[i].address);
        printf("Skip bytes:              0x%" PRIx64 "\n",binary_file_details->skips[i].bytes);
    }
    for (i=0;i<binary_file_details->patches_count;i++)
    {
        printf("Patch address:           0x%" PRIx64 "\n",binary_file_details->patches[i].address);
        printf("Patch bytes:             0x");
        phex(stdout,binary_file_details->patches[i].byte_array,binary_file_details->patches[i].length);
    }
    for (i=0;i<binary_file_details->hard_stops_count;i++)
    {
        printf("hard stop address:       0x%" PRIx64 "\n",binary_file_details->hard_stops[i].address);
        printf("hard stop location:      %d\n",binary_file_details->hard_stops[i].location);
    }
    for (i=0;i<binary_file_details->outputs_count;i++)
    {
        printf("Outputs reg:             %s\n", register_name_from_int(binary_file_details->outputs[i].reg));
        printf("Outputs address:         0x%" PRIx64 "\n",binary_file_details->outputs[i].address);
        printf("Outputs length:          0x%" PRIx64 "\n",binary_file_details->outputs[i].length);
        printf("Outputs location:        %d\n",binary_file_details->outputs[i].location);
    }
    for (i=0;i<binary_file_details->set_registers_count;i++)
    {
        printf("Set registers reg:       0%s\n",register_name_from_int(binary_file_details->set_registers[i].reg));
        printf("Set registers value:     0x%" PRIx64 "\n",binary_file_details->set_registers[i].reg_value);
    }
    for (i=0;i<binary_file_details->set_memory_count;i++)
    {
        printf("Set memory - Type:       %d\n",binary_file_details->set_memory[i].type);
        printf("Set memory - Format:     %d\n",binary_file_details->set_memory[i].format);
        printf("Set memory - Length:     %llu\n",binary_file_details->set_memory[i].length);
        printf("Set memory - Byte Array: 0x%hhn\n",binary_file_details->set_memory[i].byte_array);
        printf("Set memory - Address:    0x%" PRIx64 "\n",binary_file_details->set_memory[i].address);
        printf("Set memory - Sp Offset:  0x%" PRIx64 "\n",binary_file_details->set_memory[i].sp_offset);
    }
        printf("Memory main address:     0x%" PRIx64 "\n",binary_file_details->memory_main.address);
        printf("Memory main size:        0x%" PRIx64 "\n",binary_file_details->memory_main.size);
        printf("Stack address:           0x%" PRIx64 "\n",binary_file_details->stack.address);
        printf("Stack start address:     0x%" PRIx64 "\n",binary_file_details->stack_start_address);
        printf("Stack size:              0x%" PRIx64 "\n",binary_file_details->stack.size);

    for (i=0;i<binary_file_details->memory_other_count;i++)
    {
        printf("Memory other address:    0x%" PRIx64 "\n",binary_file_details->memory_other[i].address);
        printf("Memory other size:       0x%" PRIx64 "\n",binary_file_details->memory_other[i].size);
    }
}
