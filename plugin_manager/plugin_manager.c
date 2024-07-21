#include "plugin_manager.h"
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

void plugin_manager_init(PluginManager* manager) {
    memset(manager, 0, sizeof(PluginManager));
}

int plugin_manager_load(PluginManager* manager, const char* plugin_path) {
    if (manager->plugin_count >= MAX_PLUGINS) {
        fprintf(stderr, "Maximum number of plugins reached\n");
        return -1;
    }

    void* handle = dlopen(plugin_path, RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "Cannot open plugin %s: %s\n", plugin_path, dlerror());
        return -1;
    }

    OsxiecPlugin* plugin = dlsym(handle, "osxiec_plugin");
    if (!plugin) {
        fprintf(stderr, "Cannot load symbol osxiec_plugin: %s\n", dlerror());
        dlclose(handle);
        return -1;
    }

    if (plugin->initialize && plugin->initialize() != 0) {
        fprintf(stderr, "Plugin initialization failed\n");
        dlclose(handle);
        return -1;
    }

    manager->plugins[manager->plugin_count++] = plugin;
    printf("Loaded plugin: %s (version %s)\n", plugin->name, plugin->version);
    return 0;
}

int plugin_manager_execute(PluginManager* manager, const char* command) {
    for (int i = 0; i < manager->plugin_count; i++) {
        if (manager->plugins[i]->execute(command) == 0) {
            return 0; // Command was handled by a plugin
        }
    }
    return -1; // No plugin handled the command
}

void plugin_manager_cleanup(PluginManager* manager) {
    for (int i = 0; i < manager->plugin_count; i++) {
        if (manager->plugins[i]->cleanup) {
            manager->plugins[i]->cleanup();
        }
    }
    manager->plugin_count = 0;
}