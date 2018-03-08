/**
 * Operating Systems 2013-2017 - Assignment 2
 *
 * TODO Name, Group
 *
 */

#include <windows.h>

#include "cmd.h"
#include "utils.h"
#include "parser.h"

#define READ        0
#define WRITE        1

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
    /* TODO execute cd */

    return 0;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
    /* TODO execute exit/quit */

    return 0; /* TODO replace with actual exit code */
}

/**
 * Parse and execute a simple command, by either creating a new processing or
 * internally process it.
 */
static int
parse_simple(simple_command_t *s, int level, command_t *father, HANDLE *h)
{
    /* TODO sanity checks */
    char *command = get_argv(s);

    if (strcmp(command, "exit") == 0) {
        free(command);
        return SHELL_EXIT;
    }

    /* TODO if variable assignment, execute the assignment and return
     * the exit status
     */

    /* TODO if external command:
     *  1. set handles
     *  2. redirect standard input / output / error
     *  3. run command
     *  4. get exit code
     */
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    DWORD dwRes;
    BOOL bRes;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    si.dwFlags |= STARTF_USESTDHANDLES;

    SECURITY_ATTRIBUTES sa;
    ZeroMemory(&sa, sizeof(sa));
    sa.bInheritHandle = TRUE;

    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    char *in = get_word(s->in);
    if (in != NULL) {
        si.hStdInput = CreateFile(
            in,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &sa,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        free(in);
        DIE(si.hStdInput == INVALID_HANDLE_VALUE, "CreateFile in");
    }

    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    char *out = get_word(s->out);
    if (out != NULL) {
        si.hStdOutput = CreateFile(
            out,
            GENERIC_WRITE | GENERIC_READ,
            FILE_SHARE_WRITE | FILE_SHARE_READ,
            &sa,
            s->io_flags & IO_OUT_APPEND ? OPEN_ALWAYS : CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        DIE(si.hStdOutput == INVALID_HANDLE_VALUE, "CreateFile out");
    }

    if (s->io_flags & IO_OUT_APPEND) {
        DWORD pos = SetFilePointer(si.hStdOutput, 0, NULL, FILE_END);
        DIE(pos == INVALID_SET_FILE_POINTER, "SetFilePointer out");
    }

    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    char *err = get_word(s->err);
    bool out_and_err = false;
    if (err != NULL) {
        if (out != NULL && strcmp(out, err) == 0) {
            si.hStdError = si.hStdOutput;
            out_and_err = true;
        } else {
            si.hStdError = CreateFile(
                err,
                GENERIC_WRITE | GENERIC_READ,
                FILE_SHARE_WRITE | FILE_SHARE_READ,
                &sa,
                s->io_flags & IO_ERR_APPEND ? OPEN_ALWAYS : CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                NULL
            );
        }
        free(err);
        DIE(si.hStdError == INVALID_HANDLE_VALUE, "CreateFile err");
    }

    if (out != NULL) {
        free(out);
    }

    if (s->io_flags & IO_ERR_APPEND) {
        DWORD pos = SetFilePointer(si.hStdError, 0, NULL, FILE_END);
        DIE(pos == INVALID_SET_FILE_POINTER, "SetFilePointer err");
    }

    /* TODO if builtin command, execute the command */
    if (strcmp(get_word(s->verb), "cd") == 0) {
        BOOL ret = SetCurrentDirectory(get_word(s->params));
        DIE(ret == FALSE, "SetCurrentDirectory");
        return 0;
    }

    ZeroMemory(&pi, sizeof(pi));

    /* Start child process */
    bRes = CreateProcess(
        NULL,
        command,
        NULL,
        NULL,
        TRUE,
        0,
        NULL,
        NULL,
        &si,
        &pi
    );
    DIE(bRes == FALSE, "CreateProcess");

    if (err != NULL && !out_and_err) {
        BOOL ret = CloseHandle(si.hStdError);
        DIE(ret == FALSE, "CloseHandle err");
    }
    if (out != NULL) {
        BOOL ret = CloseHandle(si.hStdOutput);
        DIE(ret == FALSE, "CloseHandle out");
    }
    if (in != NULL) {
        BOOL ret = CloseHandle(si.hStdInput);
        DIE(ret == FALSE, "CloseHandle in");
    }

    /* Wait for the child to finish */
    dwRes = WaitForSingleObject(pi.hProcess, INFINITE);
    DIE(dwRes == WAIT_FAILED, "WaitForSingleObject");

    return true; /* TODO replace with actual exit status */
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool do_in_parallel(command_t *cmd1, command_t *cmd2, int level,
                           command_t *father)
{
    /* TODO execute cmd1 and cmd2 simultaneously */

    return true; /* TODO replace with actual exit status */
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2)
 */
static bool do_on_pipe(command_t *cmd1, command_t *cmd2, int level,
                       command_t *father)
{
    /* TODO redirect the output of cmd1 to the input of cmd2 */

    return true; /* TODO replace with actual exit status */
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father, void *h)
{
    /* TODO sanity checks */

    switch (c->op) {
    case OP_NONE:
        return parse_simple(c->scmd, level, father, h);
    case OP_SEQUENTIAL:
        /* TODO execute the commands one after the other */
        break;

    case OP_PARALLEL:
        /* TODO execute the commands simultaneously */
        break;

    case OP_CONDITIONAL_NZERO:
        /* TODO execute the second command only if the first one
         * returns non zero
         */
        break;

    case OP_CONDITIONAL_ZERO:
        /* TODO execute the second command only if the first one
         * returns zero
         */
        break;

    case OP_PIPE:
        /* TODO redirect the output of the first command to the
         * input of the second
         */
        break;

    default:
        return SHELL_EXIT;
    }

    return 0; /* TODO replace with actual exit code of command */
}
