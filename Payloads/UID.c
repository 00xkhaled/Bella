#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
int main(int argc, char **argv)
{	
	setuid(0);
	char commands[2048]; //max length
	strcpy(commands, "");
	for(int i = 1; i < argc; ++i) //use one otherwise it will call itself .
	{
		strcat(commands, argv[i]);
		strcat(commands, " ");
	}
    int x = system(commands);
    return x;
}