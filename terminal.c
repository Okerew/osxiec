#include "globals/globals.h"
#include "log/log.h"
#include "osxiec.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <termios.h>
#include <unistd.h>

void set_terminal_raw_mode() {
  struct termios raw;
  tcgetattr(STDIN_FILENO, &raw);
  raw.c_lflag &= ~(ICANON | ECHO);
  tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
}

void set_terminal_canonical_mode() {
  struct termios canonical;
  tcgetattr(STDIN_FILENO, &canonical);
  canonical.c_lflag |= (ICANON | ECHO);
  tcsetattr(STDIN_FILENO, TCSAFLUSH, &canonical);
}

void move_cursor_left(int n) {
  printf("\033[%dD", n);
  fflush(stdout);
}

void move_cursor_right(int n) {
  printf("\033[%dC", n);
  fflush(stdout);
}

void clear_line() {
  printf("\033[2K");
  fflush(stdout);
}

void add_to_history(const char *command) {
  if (history.count < MAX_HISTORY_LEN) {
    strncpy(history.commands[history.count], command, MAX_COMMAND_LEN);
    history.count++;
    history.current = history.count;
  } else {
    // Shift the history to make room for the new command
    memmove(history.commands, history.commands + 1,
            (MAX_HISTORY_LEN - 1) * MAX_COMMAND_LEN);
    strncpy(history.commands[MAX_HISTORY_LEN - 1], command, MAX_COMMAND_LEN);
  }
}

void navigate_history(char *command, int *command_index, int *cursor_pos,
                      int direction) {
  if (direction == -1 && history.current > 0) {
    history.current--;
    strncpy(command, history.commands[history.current], MAX_COMMAND_LEN);
    *command_index = strlen(command);
    *cursor_pos = *command_index;
  } else if (direction == 1 && history.current < history.count - 1) {
    history.current++;
    strncpy(command, history.commands[history.current], MAX_COMMAND_LEN);
    *command_index = strlen(command);
    *cursor_pos = *command_index;
  }
}

void signal_handler() { stop_thread = 1; }

void *logger_thread(void *arg) {
  // Sample resource usage into the container log every few seconds. The log
  // file itself is owned by the logging module (opened once in
  // container_log_init), so this thread just feeds it stats samples.
  ContainerConfig *config = (ContainerConfig *)arg;
  while (!stop_thread) {
    log_resource_usage(config);
    sleep(5);
  }
  return NULL;
}

void handle_signal(int sig) {
  if (sig == SIGINT || sig == SIGTERM) {
    // Graceful shutdown: let the main loop tear the container down.
    should_exit = 1;
    return;
  }

  // Fatal fault (SIGSEGV/SIGBUS/SIGILL/SIGFPE/SIGABRT): capture a stack trace
  // to the log, then re-raise with the default handler so the process actually
  // dies and its exit status reflects the signal (Docker-style 128+signal).
  log_crash(sig);
  signal(sig, SIG_DFL);
  raise(sig);
}
