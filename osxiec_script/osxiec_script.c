#include "osxiec_script.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../osxiec.h"

#define MAX_VARIABLES 100
#define MAX_VAR_NAME 50
#define MAX_VAR_VALUE 255
#define SCRIPT_EXTENSION ".osxs"

// Structure to hold variables
typedef struct {
    char name[MAX_VAR_NAME];
    char value[MAX_VAR_VALUE];
} Variable;

Variable variables[MAX_VARIABLES];
int variable_count = 0;

// Function prototypes
void set_variable(const char *name, const char *value);
char *get_variable(const char *name);
void replace_variables(char *line);
int evaluate_condition(const char *condition);

void execute_script(const char *script) {
    char *line = strtok((char *)script, "\n");
    while (line != NULL) {
        // Skip comments and empty lines
        if (line[0] != '#' && line[0] != '\0') {
            replace_variables(line);
            execute_cs_command(line);
        }
        line = strtok(NULL, "\n");
    }
}

void execute_script_file(const char *filename) {
    // Check if the filename ends with .osxs
    size_t len = strlen(filename);
    size_t ext_len = strlen(SCRIPT_EXTENSION);
    if (len <= ext_len || strcmp(filename + len - ext_len, SCRIPT_EXTENSION) != 0) {
        printf("Error: Invalid file extension. Expected %s\n", SCRIPT_EXTENSION);
        return;
    }

    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        printf("Error: Unable to open file %s\n", filename);
        return;
    }

    char line[MAX_COMMAND_LEN];
    while (fgets(line, sizeof(line), file)) {
        // Remove newline character if present
        size_t line_len = strlen(line);
        if (line_len > 0 && line[line_len-1] == '\n') {
            line[line_len-1] = '\0';
        }

        // Skip comments and empty lines
        if (line[0] != '#' && line[0] != '\0') {
            execute_cs_command(line);
        }
    }

    fclose(file);
}

void execute_cs_command(const char *command) {
    char cmd[MAX_COMMAND_LEN];
    char args[MAX_ARGS][MAX_COMMAND_LEN];
    int arg_count = 0;

    // Parse command and arguments
    sscanf(command, "%s", cmd);
    char *arg_start = strchr(command, ' ');
    if (arg_start != NULL) {
        arg_start++; // Move past the space
        char *token = strtok((char *)arg_start, " ");
        while (token != NULL && arg_count < MAX_ARGS) {
            strcpy(args[arg_count++], token);
            token = strtok(NULL, " ");
        }
    }

    // Convert to uppercase for case-insensitive comparison
    for (int i = 0; cmd[i]; i++) cmd[i] = toupper(cmd[i]);

    // Execute appropriate function based on command
    if (strcmp(cmd, "SET_MEMORY") == 0 && arg_count == 2) {
        long soft_limit = atol(args[0]);
        long hard_limit = atol(args[1]);
        scale_container_resources(soft_limit, hard_limit, -1); // -1 for unchanged CPU priority
    }
    else if (strcmp(cmd, "SET_CPU") == 0 && arg_count == 1) {
        int cpu_priority = atoi(args[0]);
        scale_container_resources(-1, -1, cpu_priority); // -1 for unchanged memory limits
    }
    else if (strcmp(cmd, "EXECUTE") == 0 && arg_count >= 1) {
        char full_command[MAX_COMMAND_LEN] = "";
        for (int i = 0; i < arg_count; i++) {
            strcat(full_command, args[i]);
            if (i < arg_count - 1) strcat(full_command, " ");
        }
        execute_command(full_command);
    }
    else if (strcmp(cmd, "LOG") == 0 && arg_count >= 1) {
        char message[MAX_COMMAND_LEN] = "";
        for (int i = 0; i < arg_count; i++) {
            strcat(message, args[i]);
            if (i < arg_count - 1) strcat(message, " ");
        }
        printf("LOG: %s\n", message);
    }
    else if (strcmp(cmd, "EXECUTE_FILE") == 0 && arg_count == 1) {
        execute_script_file(args[0]);
    }
    else if (strcmp(cmd, "SET") == 0 && arg_count == 2) {
        set_variable(args[0], args[1]);
    }
    else if (strcmp(cmd, "IF") == 0 && arg_count >= 2) {
        if (evaluate_condition(args[0])) {
            char subcommand[MAX_COMMAND_LEN] = "";
            for (int i = 1; i < arg_count; i++) {
                strcat(subcommand, args[i]);
                if (i < arg_count - 1) strcat(subcommand, " ");
            }
            execute_cs_command(subcommand);
        }
    }
    else if (strcmp(cmd, "SLEEP") == 0 && arg_count == 1) {
        int sleep_time = atoi(args[0]);
        sleep(sleep_time);
    }

}

void set_variable(const char *name, const char *value) {
    for (int i = 0; i < variable_count; i++) {
        if (strcmp(variables[i].name, name) == 0) {
            strcpy(variables[i].value, value);
            return;
        }
    }
    if (variable_count < MAX_VARIABLES) {
        strcpy(variables[variable_count].name, name);
        strcpy(variables[variable_count].value, value);
        variable_count++;
    } else {
        printf("Error: Maximum number of variables reached\n");
    }
}

char *get_variable(const char *name) {
    for (int i = 0; i < variable_count; i++) {
        if (strcmp(variables[i].name, name) == 0) {
            return variables[i].value;
        }
    }
    return NULL;
}

void replace_variables(char *line) {
    char *var_start, *var_end;
    char var_name[MAX_VAR_NAME];
    char *var_value;
    char new_line[MAX_COMMAND_LEN];

    while ((var_start = strchr(line, '$')) != NULL) {
        var_end = strchr(var_start, ' ');
        if (var_end == NULL) var_end = var_start + strlen(var_start);

        strncpy(var_name, var_start + 1, var_end - var_start - 1);
        var_name[var_end - var_start - 1] = '\0';

        var_value = get_variable(var_name);
        if (var_value != NULL) {
            strcpy(new_line, line);
            new_line[var_start - line] = '\0';
            strcat(new_line, var_value);
            strcat(new_line, var_end);
            strcpy(line, new_line);
        } else {
            // Variable not found, move past this occurrence
            line = var_end;
        }
    }
}

int evaluate_condition(const char *condition) {
    // Simple condition evaluation (you can expand this)
    char var_name[MAX_VAR_NAME];
    char expected_value[MAX_VAR_VALUE];
    sscanf(condition, "%s==%s", var_name, expected_value);

    char *actual_value = get_variable(var_name);
    if (actual_value != NULL) {
        return strcmp(actual_value, expected_value) == 0;
    }
    return 0;
}