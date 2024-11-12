// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	int ret;

	if (dir == NULL)
		return 0;

	char *path = get_word(dir);

	ret = chdir(path);
	free(path);
	return ret;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	return SHELL_EXIT;
}

void redirectFunction(simple_command_t *s)
{
	int out_file, err_file;
	char *out_file_name, *error_file_name;

	out_file_name = get_word(s->out);
	error_file_name = get_word(s->err);

	if (s->out != NULL && s->err != NULL && strcmp(out_file_name, error_file_name) == 0) {
		out_file = open(out_file_name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		dup2(out_file, STDOUT_FILENO);
		dup2(out_file, STDERR_FILENO);
		close(out_file);
	} else {
		if (s->out != NULL) {
			if (s->io_flags == IO_REGULAR)
				out_file = open(out_file_name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
			else if (s->io_flags == IO_OUT_APPEND)
				out_file = open(out_file_name, O_WRONLY | O_CREAT | O_APPEND, 0644);

			dup2(out_file, STDOUT_FILENO);
			close(out_file);
		}
		if (s->err != NULL) {
			if (s->io_flags == IO_REGULAR)
				err_file = open(error_file_name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
			else if (s->io_flags == IO_ERR_APPEND)
				err_file = open(error_file_name, O_WRONLY | O_CREAT | O_APPEND, 0644);

			dup2(err_file, STDERR_FILENO);
			close(err_file);
		}
	}
	free(out_file_name);
	free(error_file_name);
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	int in_file, ret, i;
	int buff_read, buff_write, buff_error;
	int status, number_of_arguments = 0;

	char *in_file_name;
	char *command;
	char **args;

	command = get_word(s->verb);
	args = get_argv(s, &number_of_arguments);

	if (strcmp(command, "exit") == 0 || strcmp(command, "quit") == 0) {
		free(command);
		for (i = 0; i < number_of_arguments; i++)
			free(args[i]);
		free(args);
		return shell_exit();
	}

	buff_read = dup(STDIN_FILENO);
	buff_write = dup(STDOUT_FILENO);
	buff_error = dup(STDERR_FILENO);

	if (strcmp(command, "cd") == 0) {
		redirectFunction(s);
		ret = shell_cd(s->params);

		dup2(buff_read, STDIN_FILENO);
		dup2(buff_write, STDOUT_FILENO);
		dup2(buff_error, STDERR_FILENO);
		close(buff_error);
		close(buff_read);
		close(buff_write);

		free(command);
		for (i = 0; i < number_of_arguments; i++)
			free(args[i]);
		free(args);
		return ret;
	}
	if (strstr(command, "=") != NULL) {
		char *cmd = command;
		char *name = strtok_r(command, "=", &cmd);
		char *value = strtok_r(NULL, "=", &cmd);

		ret = setenv(name, value, 1);
		close(buff_error);
		close(buff_read);
		close(buff_write);

		free(command);
		for (i = 0; i < number_of_arguments; i++)
			free(args[i]);
		free(args);
		return ret;
	}

	pid_t id = fork();

	if (id == 0) {
		if (s->in != NULL) {
			in_file_name = get_word(s->in);
			in_file = open(in_file_name, O_RDONLY);
			dup2(in_file, STDIN_FILENO);
			free(in_file_name);
			close(in_file);
		}
		redirectFunction(s);
		ret = execvp(command, args);
		if (ret < 0)
			fprintf(stderr, "Execution failed for '%s'\n", command);

		exit(ret);

	} else {
		waitpid(id, &status, 0);
		dup2(buff_read, STDIN_FILENO);
		dup2(buff_write, STDOUT_FILENO);
		dup2(buff_error, STDERR_FILENO);
		close(buff_error);
		close(buff_read);
		close(buff_write);

		free(command);
		for (i = 0; i < number_of_arguments; i++)
			free(args[i]);
		free(args);
		if (WIFEXITED(status)) {
			int exit = WEXITSTATUS(status);
			return exit;
		}
	}
	return 0;
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	pid_t id;
	int ret, status;

	id = fork();
	if (id == 0) {
		ret = parse_command(cmd1, level + 1, father);
		exit(ret);
	} else {
		ret = parse_command(cmd2, level + 1, father);

		waitpid(id, &status, 0);

		if (WIFEXITED(status)) {
			int exit = WEXITSTATUS(status) | ret;
			return exit;
		}
	}
	return 0;
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	int fd[2];
	int ret, status1, status2;
	pid_t id1, id2;

	pipe(fd);

	id1 = fork();
	if (id1 == 0) {
		close(fd[0]);
		dup2(fd[1], STDOUT_FILENO);
		close(fd[1]);

		ret = parse_command(cmd1, level + 1, father);
		exit(ret);
	} else {
		id2 = fork();
		if (id2 == 0) {
			close(fd[1]);
			dup2(fd[0], STDIN_FILENO);
			close(fd[0]);

			ret = parse_command(cmd2, level + 1, father);
			exit(ret);
		} else {
			close(fd[0]);
			close(fd[1]);

			waitpid(id1, &status1, 0);
			waitpid(id2, &status2, 0);

			if (WIFEXITED(status2)) {
				int exit = WEXITSTATUS(status2);
				return exit;
			}
		}
	}
	return 0;
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	int ret;

	if (c->op == OP_NONE) {
		ret = parse_simple(c->scmd, level + 1, c);

		return ret;
	}

	switch (c->op) {
	case OP_SEQUENTIAL:
		ret = parse_command(c->cmd1, level + 1, c);
		ret += parse_command(c->cmd2, level + 1, c);
		break;

	case OP_PARALLEL:
		ret = run_in_parallel(c->cmd1, c->cmd2, level + 1, c);
		break;

	case OP_CONDITIONAL_NZERO:
		ret = parse_command(c->cmd1, level + 1, c);
		if (ret != 0)
			ret = parse_command(c->cmd2, level + 1, c);
		break;

	case OP_CONDITIONAL_ZERO:
		ret = parse_command(c->cmd1, level + 1, c);
		if (ret == 0)
			ret = parse_command(c->cmd2, level + 1, c);
		break;

	case OP_PIPE:
		ret = run_on_pipe(c->cmd1, c->cmd2, level + 1, c);
		break;

	default:
		return SHELL_EXIT;
	}

	return ret;
}
