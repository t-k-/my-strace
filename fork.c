#include  <stdio.h>
#include  <sys/types.h>

void  main(void)
{
	pid_t  pid;
	fork();
	pid = getpid();
	printf("This line is from pid %d\n", pid);
}
