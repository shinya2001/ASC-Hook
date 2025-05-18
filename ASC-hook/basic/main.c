#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

typedef long (*syscall_fn_t)(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t);

static syscall_fn_t next_sys_call = NULL;

/*
You can add any operations here that need to be performed before executing the system call.
`hook_function` is called in the general interception flow.
`final_signal_hook_function` is called in the signal-based interception flow.
*/
static long hook_function(int64_t x0,int64_t x1,int64_t x2,int64_t x3,int64_t x4,int64_t x5,int64_t x6,int64_t x7,int64_t x8,int64_t x9,int64_t x10,int64_t x11,int64_t x12,int64_t x13,int64_t x14,int64_t x15,int64_t x16,int64_t x17,int64_t x30)
{
	printf("output from hook_function: syscall number %ld\n", x8);
	return next_sys_call(x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17, x30);
}


void final_signal_hook_function(int64_t x0,int64_t x1,int64_t x2,int64_t x3,int64_t x4,int64_t x5,int64_t x6,int64_t x7,int64_t x8,int64_t x9,int64_t x10,int64_t x11,int64_t x12,int64_t x13,int64_t x14,int64_t x15,int64_t x16,int64_t x17,int64_t x30)
{
    printf("signal:output from hook_function: syscall number %ld\n",x8);
		
}

int __hook_init(long placeholder __attribute__((unused)),
		void *sys_call_hook_ptr)
{
	printf("output from __hook_init: we can do some init work here\n");
	next_sys_call = *((syscall_fn_t *) sys_call_hook_ptr);
	*((syscall_fn_t *) sys_call_hook_ptr) = hook_function;

	return 0;
}


void final_print(int x){
	printf("yaHI!!!!!!!!!:%d\n",x);
	
}

void final_exit(){
	exit(0);
}
#define MAX_BUFFER_SIZE 4096
void final_write(int syscall_num) {
    FILE *file;
    char *filename = "./syscallSwitch.config";
    char buffer[MAX_BUFFER_SIZE];
    char num_str[12];
    char *token;
    int found = 0;
    char first_line[MAX_BUFFER_SIZE];
    char second_line[MAX_BUFFER_SIZE];
    char third_line[MAX_BUFFER_SIZE];
    char remaining_lines[MAX_BUFFER_SIZE * 10] = ""; 

    
    snprintf(num_str, sizeof(num_str), "%d", syscall_num);

    file = fopen(filename, "r+");
    if (!file) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    if (fgets(first_line, sizeof(first_line), file) == NULL) {
        perror("Error reading file");
        fclose(file);
        return;
    }
    if (fgets(second_line, sizeof(second_line), file) == NULL) {
        perror("Error reading file");
        fclose(file);
        return;
    }

    if (fgets(third_line, sizeof(third_line), file) == NULL) {
        perror("Error reading file");
        fclose(file);
        return;
    }

    third_line[strcspn(third_line, "\n")] = 0;

    char *prefix = "system call number need to be pass:";
    char *syscalls = strstr(third_line, prefix);
    if (syscalls == NULL) {
        fprintf(stderr, "Invalid config format\n");
        fclose(file);
        return;
    }

    syscalls += strlen(prefix);

    while (*syscalls == ' ') syscalls++;
    char temp_buffer[MAX_BUFFER_SIZE];
    strcpy(temp_buffer, syscalls);

    token = strtok(temp_buffer, ",");
    while (token != NULL) {
        if (strcmp(token, num_str) == 0) {
            found = 1;
            break;
        }
        token = strtok(NULL, ",");
    }

    if (!found) {
        char *remaining = remaining_lines;
        while (fgets(remaining, sizeof(buffer), file) != NULL) {
            remaining += strlen(remaining);
        }

        fseek(file, 0, SEEK_SET);

        fprintf(file, "%s", first_line);
        fprintf(file, "%s", second_line);

        if (strlen(syscalls) > 0) {
            fprintf(file, "%s %s,%s\n", prefix, syscalls, num_str);
        } else {
            fprintf(file, "%s %s\n", prefix, num_str);
        }

        fprintf(file, "%s", remaining_lines);
    }

    fclose(file);
}

void final_write2(char *param1, long long param2) {
    FILE *file;
    char *filename = "./syscallplace.config";
    char buffer[256];
    int exists = 0;

    file = fopen(filename, "a+");
    if (!file) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    while (fgets(buffer, sizeof(buffer), file)) {
        char file_param1[256];
        long long file_param2;

        if (sscanf(buffer, "%s %lld", file_param1, &file_param2) == 2) {
            if (strcmp(file_param1, param1) == 0 && file_param2 == param2) {
                exists = 1;
                break;
            }
        }
    }

    if (!exists) {
        fprintf(file, "%s %lld\n", param1, param2);
    }

    fclose(file);
}