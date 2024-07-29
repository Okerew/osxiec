#ifndef CONTAINER_SCRIPT_H
#define CONTAINER_SCRIPT_H

#define MAX_COMMAND_LEN 1024
#define MAX_ARGS 10

void execute_script(const char *script);
void execute_cs_command(const char *command);
void execute_script_file(const char *filename);
#endif // CONTAINER_SCRIPT_H