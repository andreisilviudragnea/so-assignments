/**
 * Operating Sytems 2013-2017 - Assignment 2
 *
 * TODO Name, Group
 *
 */

#ifndef _CMD_H
#define _CMD_H

#include "parser.h"
#include <windows.h>

#define SHELL_EXIT 100

/**
 * Parse and execute a command.
 */
DWORD parse_command(command_t *cmd, HANDLE hStdin, HANDLE hStdout);

#endif /* _CMD_H */
