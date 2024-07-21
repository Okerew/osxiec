#ifndef PLUGIN_H
#define PLUGIN_H

typedef struct {
    const char* name;
    const char* version;
    int (*initialize)(void);
    int (*execute)(const char* command);
    int (*cleanup)(void);
} OsxiecPlugin;

#endif