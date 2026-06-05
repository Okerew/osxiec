#ifndef PLUGIN_MANAGER_H
#define PLUGIN_MANAGER_H

#include "plugin.h"

#define MAX_PLUGINS 50

typedef struct {
    OsxiecPlugin* plugins[MAX_PLUGINS];
    int plugin_count;
} PluginManager;

void plugin_manager_init(PluginManager* manager);
int plugin_manager_load(PluginManager* manager, const char* plugin_path);
int plugin_manager_execute(PluginManager* manager, const char* command);
void plugin_manager_cleanup(PluginManager* manager);

#endif