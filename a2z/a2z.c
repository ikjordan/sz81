/* gcc -o a2z a2z.c
*/

#include <stdio.h>

#ifdef E04
static char ascii2zx[96]=
  {
  0,143,11,12,13,143,143,11,16,17,20,19,26,18,27,21,
  28,29,30,31,32,33,34,35,36,37,14,25,24,22,23,15,
  143,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,
  53,54,55,56,57,58,59,60,61,62,63,143,143,143,143,143,
  143,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,
  53,54,55,56,57,58,59,60,61,62,63,143,143,143,143,143
  };
#endif

#ifdef E07
static char ascii2zx[96]=
  {
  0,143,11,12,13,143,143,11,16,17,23,21,26,22,27,24,
  28,29,30,31,32,33,34,35,36,37,14,25,19,20,18,15,
  143,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,
  53,54,55,56,57,58,59,60,61,62,63,143,143,143,143,143,
  143,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,
  53,54,55,56,57,58,59,60,61,62,63,143,143,143,143,143
  };
#endif

int main()
{
	int c;

	putchar(0x76);
	for (;;) {
	  c = getchar();
	  if (c==EOF) break;
	  if (c==0x0a) c=0x76; else c=ascii2zx[c-32];
	  putchar(c);
	}

	return 0;
}
