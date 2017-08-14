#include <stdio.h>

const int cint = 1;


int main()
{
	int *p = NULL;
	char *s = "hello world";
	int v = 2;
	printf("%d\n", cint);
	printf("%s\n", s);
	printf("%d\n", v);

	//s[2] = 'M';

	p = (int*)&v;
	*p = 8;
	
	printf("%d\n", cint);
	printf("%s\n", s);
	printf("%d\n", v);


	return 0;
}
