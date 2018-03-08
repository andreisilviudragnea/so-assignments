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

static HANDLE
create_process(LPSTR command, HANDLE hStdin, HANDLE hStdout, HANDLE hStdErr)
{
    STARTUPINFO si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags |= STARTF_USESTDHANDLES;
    si.hStdInput = hStdin;
    si.hStdOutput = hStdout;
    si.hStdError = hStdErr;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    BOOL ret = CreateProcess(NULL, command, NULL, NULL, TRUE, 0, NULL, NULL,
                             &si, &pi);
    DIE(ret == FALSE, "CreateProcess");

    return pi.hProcess;
}

static void
redirect(const simple_command_t *s, PHANDLE hStdInput, PHANDLE hStdOutput,
         PHANDLE hStdError)
{
    SECURITY_ATTRIBUTES sa;
    ZeroMemory(&sa, sizeof(sa));
    sa.bInheritHandle = TRUE;

    char *in = get_word(s->in);
    if (in != NULL) {
        *hStdInput = CreateFile(
            in,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &sa,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        free(in);
        DIE(*hStdInput == INVALID_HANDLE_VALUE, "CreateFile in");
    }

    char *out = get_word(s->out);
    if (out != NULL) {
        *hStdOutput = CreateFile(
            out,
            GENERIC_WRITE | GENERIC_READ,
            FILE_SHARE_WRITE | FILE_SHARE_READ,
            &sa,
            s->io_flags & IO_OUT_APPEND ? OPEN_ALWAYS : CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        DIE(*hStdOutput == INVALID_HANDLE_VALUE, "CreateFile out");
    }

    if (s->io_flags & IO_OUT_APPEND) {
        DWORD pos = SetFilePointer(*hStdOutput, 0, NULL, FILE_END);
        DIE(pos == INVALID_SET_FILE_POINTER, "SetFilePointer out");
    }

    char *err = get_word(s->err);
    bool out_and_err = false;
    if (err != NULL) {
        if (out != NULL && strcmp(out, err) == 0) {
            *hStdError = *hStdOutput;
            out_and_err = true;
        } else {
            *hStdError = CreateFile(
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
        DIE(*hStdError == INVALID_HANDLE_VALUE, "CreateFile err");
    }

    if (out != NULL) {
        free(out);
    }

    if (s->io_flags & IO_ERR_APPEND) {
        DWORD pos = SetFilePointer(*hStdError, 0, NULL, FILE_END);
        DIE(pos == INVALID_SET_FILE_POINTER, "SetFilePointer err");
    }
}

static HANDLE
redirect_and_create_process(const simple_command_t *s, PHANDLE hStdInput,
                            PHANDLE hStdOutput, PHANDLE hStdError)
{
    redirect(s, hStdInput, hStdOutput, hStdError);

    HANDLE hProcess = create_process(get_argv(s), *hStdInput, *hStdOutput,
                                     *hStdError);

    if (*hStdError != GetStdHandle(STD_ERROR_HANDLE) &&
        *hStdError != *hStdOutput) {
        BOOL ret = CloseHandle(*hStdError);
        DIE(ret == FALSE, "CloseHandle err");
    }
    if (*hStdOutput != GetStdHandle(STD_OUTPUT_HANDLE)) {
        BOOL ret = CloseHandle(*hStdOutput);
        DIE(ret == FALSE, "CloseHandle out");
    }
    if (*hStdInput != GetStdHandle(STD_INPUT_HANDLE)) {
        BOOL ret = CloseHandle(*hStdInput);
        DIE(ret == FALSE, "CloseHandle in");
    }

    return hProcess;
}

/**
 * Parse and execute a simple command, by either creating a new processing or
 * internally process it.
 */
static DWORD
parse_simple(simple_command_t *s, int level, command_t *father, HANDLE h)
{
    /* TODO sanity checks */
    char *command = get_argv(s);

    if (strcmp(command, "exit") == 0) {
        free(command);
        return SHELL_EXIT;
    }

    if (strchr(get_argv(s), '=') != NULL) {
        BOOL ret = SetEnvironmentVariable(s->verb->string,
                                          s->verb->next_part->next_part->string);
        return ret == FALSE ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    HANDLE hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE hStdError = GetStdHandle(STD_ERROR_HANDLE);
    redirect(s, &hStdInput, &hStdOutput, &hStdError);

    /* TODO if builtin command, execute the command */
    if (strcmp(get_word(s->verb), "cd") == 0) {
        BOOL ret = SetCurrentDirectory(get_word(s->params));
        return ret == FALSE ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    HANDLE hProcess = create_process(command, hStdInput, hStdOutput, hStdError);

    if (hStdError != GetStdHandle(STD_ERROR_HANDLE) &&
        hStdError != hStdOutput) {
        BOOL ret = CloseHandle(hStdError);
        DIE(ret == FALSE, "CloseHandle err");
    }
    if (hStdOutput != GetStdHandle(STD_OUTPUT_HANDLE)) {
        BOOL ret = CloseHandle(hStdOutput);
        DIE(ret == FALSE, "CloseHandle out");
    }
    if (hStdInput != GetStdHandle(STD_INPUT_HANDLE)) {
        BOOL ret = CloseHandle(hStdInput);
        DIE(ret == FALSE, "CloseHandle in");
    }

    DWORD dwRes = WaitForSingleObject(hProcess, INFINITE);
    DIE(dwRes == WAIT_FAILED, "WaitForSingleObject");

    BOOL bRes = GetExitCodeProcess(hProcess, &dwRes);
    DIE(bRes == FALSE, "GetExitCode");

    return dwRes;
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
static DWORD do_on_pipe(command_t *cmd1, command_t *cmd2, int level,
                        command_t *father)
{
    HANDLE readPipe;
    HANDLE writePipe;
    SECURITY_ATTRIBUTES sa;
    memset(&sa, 0, sizeof(sa));
    sa.bInheritHandle = TRUE;
    BOOL ret = CreatePipe(&readPipe, &writePipe, &sa, 0);
    DIE(ret == FALSE, "CreatePipe");

    HANDLE hProcess1;
    {
        HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
        HANDLE hStderr1 = GetStdHandle(STD_ERROR_HANDLE);
        hProcess1 = redirect_and_create_process(cmd1->scmd, &hStdin, &writePipe,
                                                &hStderr1);
    }

    HANDLE hProcess2;
    {
        HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
        HANDLE hStderr2 = GetStdHandle(STD_ERROR_HANDLE);
        hProcess2 = redirect_and_create_process(cmd2->scmd, &readPipe, &hStdout,
                                                &hStderr2);
    }

    DWORD dwRes = WaitForSingleObject(hProcess1, INFINITE);
    DIE(dwRes == WAIT_FAILED, "WaitForSingleObject");

    dwRes = WaitForSingleObject(hProcess2, INFINITE);
    DIE(dwRes == WAIT_FAILED, "WaitForSingleObject");

    BOOL bRes = GetExitCodeProcess(hProcess2, &dwRes);
    DIE(bRes == FALSE, "GetExitCode");

    return dwRes;
}

/**
 * Parse and execute a command.
 */
DWORD parse_command(command_t *c, int level, command_t *father, HANDLE h)
{
    switch (c->op) {
    case OP_NONE:
        return parse_simple(c->scmd, level, father, h);
    case OP_SEQUENTIAL:
        parse_command(c->cmd1, level, father, h);
        return parse_command(c->cmd2, level, father, h);
    case OP_PARALLEL:
        /* TODO execute the commands simultaneously */
        break;

    case OP_CONDITIONAL_NZERO: {
        DWORD ret = parse_command(c->cmd1, level, father, h);
        if (ret == EXIT_SUCCESS) {
            return ret;
        } else {
            return parse_command(c->cmd2, level, father, h);
        }
    }

    case OP_CONDITIONAL_ZERO: {
        DWORD ret = parse_command(c->cmd1, level, father, h);
        if (ret != EXIT_SUCCESS) {
            return ret;
        } else {
            return parse_command(c->cmd2, level, father, h);
        }
    }

    case OP_PIPE:
        return do_on_pipe(c->cmd1, c->cmd2, level, father);

    default:
        return SHELL_EXIT;
    }

    return 0; /* TODO replace with actual exit code of command */
}
