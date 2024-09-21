// sample_plugin.c
#include "plugin_manager/plugin.h"
#include <stdio.h>
#include <string.h>
#include "osxiec.h"

static int sample_initialize(void) {
    printf("Sample plugin initialized\n");
    execute_command("echo hello", "");
    return 0;
}

static int sample_execute(const char* command) {
    if (strcmp(command, "sample") == 0) {
        printf("Sample plugin executed\n");
        return 0;
    }
    return -1; // Command not handled
}

static int sample_cleanup(void) {
    printf("Sample plugin cleaned up\n");
    return 0;
}

OsxiecPlugin osxiec_plugin = {
    .name = "Sample Plugin",
    .version = "1.0",
    .initialize = sample_initialize,
    .execute = sample_execute,
    .cleanup = sample_cleanup
};
