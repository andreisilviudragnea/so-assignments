#ifndef _CMD_H
#define _CMD_H

#include "parser.h"
#include <windows.h>

#define SHELL_EXIT 100

#ifdef __cplusplus
extern "C" {
#endif

DWORD parse_command(command_t *cmd, HANDLE hStdin, HANDLE hStdout, bool wait);

#ifdef __cplusplus
}
#endif

#endif /* _CMD_H */
