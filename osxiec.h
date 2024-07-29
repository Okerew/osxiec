#ifndef OSXIEC_H
#define OSXIEC_H

void execute_command(const char *command);

void scale_container_resources(int soft_limit, int hard_limit, int cpu_priority);
#endif //OSXIEC_H
