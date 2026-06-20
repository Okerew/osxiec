#ifndef OSXIEC_LOG_H
#define OSXIEC_LOG_H

#include "../osxiec.h" // ContainerConfig, get_cpu_usage, MAX_PATH_LEN

// Structured, Docker-style container logging. Every line written to the
// container log carries an ISO-8601 UTC timestamp, a severity level and a
// category, e.g.
//
//   2026-06-19T12:34:56Z [INFO ] [exec] command="ls -la" exited code=0
//
// The log lives at <container_root>/var/log/log.txt and is shared between the
// main shell thread and the periodic logger thread, so all writes are
// serialized behind an internal mutex.

typedef enum {
  LOG_DEBUG = 0,
  LOG_INFO,
  LOG_WARN,
  LOG_ERROR,
  LOG_FATAL,
} LogLevel;

// Open (append) the container log under <container_root>/var/log/. Idempotent:
// a second call while already open is a no-op. Returns 0 on success, -1 if the
// log file could not be opened.
int container_log_init(const char *container_root);

// Core logger. Thread-safe. Does nothing if the log is not open.
void container_log(LogLevel level, const char *category, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

// Convenience helpers for the common event kinds.
void log_command_exec(const char *command); // a command line was entered
void log_command_result(const char *command, int wait_status); // exit/signal
void log_resource_usage(const ContainerConfig *config);        // stats sample
void log_crash(int sig); // async-signal-safe stack-trace dump for fatal faults

// Flush and close the log file.
void container_log_close(void);

#endif // OSXIEC_LOG_H
