#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <string.h>

#define OFFSETOF(type, field) ((unsigned long)&(((type *) 0)->field))

#define SC_OFFSET_NUMBER    OFFSETOF(struct user_regs_struct, orig_rax)
#define SC_OFFSET_RETCODE   OFFSETOF(struct user_regs_struct, rax)

/* this should be found at unistd_64.h */
#define SC_READ   0
#define SC_WRITE  1
#define SC_OPEN   2
#define SC_CLOSE  3
#define SC_EXECVE 59
#define SC_CLONE  56

#define PEEK_STR(_reg) \
	peek_string(child, OFFSETOF(struct user_regs_struct, _reg))

#define PRI_IF_SET(_opt) \
	if ((tmp_long & _opt) || _opt == 0x0) \
		printf(#_opt " ")

#define IF_SET(_opt) \
	if ((tmp_long & _opt) || _opt == 0x0)

void explain_system_call(pid_t, int);

char *peek_str_at(pid_t child, long addr)
{
	union {
		char a[8];
		long b;
	} piece;

	int i, j = 0;
	char flag = 0;
	static char str[4096];

	do {
		piece.b = ptrace(PTRACE_PEEKDATA, child, addr + j, NULL);
		for (i = 0; i < sizeof(piece); i++, j++) {
			str[j] = piece.a[i];
			if (piece.a[i] == '\0') {
				flag = 1;
				break;
			}
		}
	} while (!flag); 

	return str;
}

char *peek_string(pid_t child, unsigned long reg)
{
	long addr = ptrace(PTRACE_PEEKUSER, child, reg, NULL); 
	return peek_str_at(child, addr);
}

#define PEEK_LONG(_reg) \
	peek_long(child, OFFSETOF(struct user_regs_struct, _reg))

long peek_long(pid_t child, unsigned long reg)
{
	return ptrace(PTRACE_PEEKUSER, child, reg, NULL); 
}

#define PEEK_PTR_LONG(_reg) \
	peek_ptr_long(child, OFFSETOF(struct user_regs_struct, _reg))

long peek_ptr_long(pid_t child, unsigned long reg)
{
	long addr = ptrace(PTRACE_PEEKUSER, child, reg, NULL); 
	return ptrace(PTRACE_PEEKDATA, child, addr, NULL);
}

void trace(pid_t pid, int indent)
{
	
	int status;

	ptrace(PTRACE_ATTACH, pid, NULL, NULL);

	do {
		ptrace(PTRACE_SYSCALL, pid, 0, 0);
		waitpid(pid, &status, 0);

		if (WSTOPSIG(status) == SIGTRAP) {
		 /* There are three reasons why the 
		  * child might stop with SIGTRAP:
		  *  1) syscall entry
		  *  2) syscall exit
		  *  3) child calls exec
		  */
			explain_system_call(pid, indent);
		}

	/* when child is not exiting */
	} while (!WIFEXITED(status));

}

void print_indent(int indent)
{
	int i;
	for (i = 0; i < indent; i++)
		printf("  ");
}

void explain_system_call(pid_t child, int indent)
{
	unsigned int num, ret;
	char *tmp_str;
	long tmp_long;

	num = ptrace(PTRACE_PEEKUSER, child, 
	             SC_OFFSET_NUMBER, NULL);
	ret = ptrace(PTRACE_PEEKUSER, child, 
	             SC_OFFSET_RETCODE, NULL);

	if (num == SC_OPEN) {
		tmp_str = PEEK_STR(rdi);
		tmp_long = PEEK_LONG(rsi);

		//IF_SET(O_CREAT) {
		{
			print_indent(indent);
			printf("%d: open ");
//			printf("(flags=0x%lx i.e. ", child,
//			       tmp_long);
//			PRI_IF_SET(O_RDONLY);
//			PRI_IF_SET(O_WRONLY);
//			PRI_IF_SET(O_RDWR);
//			PRI_IF_SET(O_APPEND);
//			PRI_IF_SET(O_ASYNC);
//			PRI_IF_SET(O_CLOEXEC);
//			PRI_IF_SET(O_CREAT);
//			PRI_IF_SET(O_DIRECTORY);
//			PRI_IF_SET(O_DSYNC);
//			PRI_IF_SET(O_EXCL);
//			PRI_IF_SET(O_NOCTTY);
//			PRI_IF_SET(O_NOFOLLOW);
//			PRI_IF_SET(O_NONBLOCK);
//			PRI_IF_SET(O_NDELAY);
//			PRI_IF_SET(O_SYNC);
//			PRI_IF_SET(O_TRUNC);
//			printf(")");

			printf(" %s\n", tmp_str);
		}
	} else if (num == SC_EXECVE) {
		print_indent(indent);
		printf("%d: exe ", child);
		tmp_long = PEEK_LONG(rdi);
		if (tmp_long)
			printf("%s", PEEK_STR(rdi));
		printf("\n");
		//tmp_str = ;
	//	printf("%s]\n", tmp_str);

	} else if (num == SC_CLONE) {
		print_indent(indent);
		printf("%d: clone!\n", child);
//		tmp_long = PEEK_PTR_LONG(rdx);
//		printf("parent_tid: %ld\n", tmp_long);
//		tmp_long = PEEK_PTR_LONG(r10);
//		printf("child_tid: %ld\n", tmp_long);
		tmp_long = PEEK_LONG(rax);

		print_indent(indent);
		printf("%d: return: %ld\n", child, tmp_long);

		if (tmp_long > 0) {
			printf("\n");
			trace(tmp_long, indent + 1);
			printf("\n");
		}
	}
}

int do_run(int argn, char **argv)
{
	ptrace(PTRACE_TRACEME, 0, NULL, NULL);
	int i;
//	printf("exec: ");
//	for (i = 0; i < argn; i++) {
//		printf("%s ", argv[i]);
//	}
//	printf("\n");

//	if (argv[i] != NULL) {
//		printf("argv not NULL terminated.\n");
//		return 0;
//	}

	return execvp(argv[0], argv + 0);
}

int do_trace(pid_t child)
{
	int status;

	do {
		ptrace(PTRACE_SYSCALL, child, 0, 0);
		waitpid(child, &status, 0);

		if (WSTOPSIG(status) == SIGTRAP) {
		 /* There are three reasons why the 
		  * child might stop with SIGTRAP:
		  *  1) syscall entry
		  *  2) syscall exit
		  *  3) child calls exec
		  */
			explain_system_call(child, 0);
		}

	/* when child is not exiting */
	} while (!WIFEXITED(status));

    return 0;
}

int main(int argn, char **argv)
{
	pid_t child = fork();

	if (child == -1) {
		printf("fork error. \n");
	} else if (child == 0) {
		printf("tracee pid %d\n", getpid());

		return do_run(argn - 1, argv + 1);
	} else {
		printf("tracer pid %d\n", getpid());

		return do_trace(child);
	}

	return 0;
}
