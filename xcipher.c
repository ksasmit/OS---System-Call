#include  <asm/unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <ctype.h>
#include <openssl/md5.h>

#ifndef __NR_xcrypt
#error xcrypt system call not defined
#endif

int help(int);
char *str2md5(const char *str, int length);

//structure block to be sent on kernel side as function argument
struct myargs
{
	int key_len;
	int flags;//1 - encryption 0- decryption
    char arg[4][80];//0- type of cipher 1-key 2-infile 3-outfile
};

// This function converts any string to MD5 hash characters
char *str2md5(const char *str, int length) 
{
    int n;
    MD5_CTX c;
    unsigned char digest[16];
    char *out = (char*)malloc(33);
    MD5_Init(&c);
    while (length > 0) 
	{
        if (length > 512) 
		{
            MD5_Update(&c, str, 512);
        } 
		else 
		{
            MD5_Update(&c, str, length);
        }
        length -= 512;
        str += 512;
    }
    MD5_Final(digest, &c);
    for (n = 0; n < 16; ++n) 
	{
        snprintf(&(out[n*2]), 16*2, "%02x", (unsigned int)digest[n]);
    }
    return out;
}

//This function displays help in calling the system xcrypt call
int help(int r)
{
	if(r<0)
		printf("\n The command entered is not proper\n ");
	printf("\n Help\n ");
	printf("\n-------------------------------------------------------------------------------------\n");
	printf("\nenter one or more option as under\n\n");
	printf("\n./xcipher -<e/d> -c <cipher type> -p \"<key>\" <infile> <outfile> [-h for help]");
	printf("\n-------------------------------------------------------------------------------------\n");
	return r;
}

int main (int argc, char **argv)
{
	char *cvalue = NULL,*output = NULL;
	int index;
	int c;
	int rc;
	int i = 0;int j=0;
	char str[80];
	struct myargs args;
	args.flags = -1;
	int count =0;
	FILE *file = NULL;
	opterr = 0;
	if(argc<5 && argc !=2)
	{
		printf("\n Insufficient no. of arguments entered");
		help(-1);
		return -1;
	}
	if(argc>9)
	{
		printf("\n More than required arguments entered");
		help(-1);
		return -1;
	}
	while ((c = getopt (argc, argv, "edc:p:h")) != -1)
	switch (c)
	{
		case 'e':
		{
			if(args.flags==-1)
			{
				args.flags = 1;
				count++;
				break;
			}
			else
			{
				help(-1);
				return (-1);
			}
		}
		case 'd':
		{
			if(args.flags == -1)
			{
				args.flags = 0;
				count++;
				break;
			}
			else
			{
				help(-1);
				return (-1);
			}
		}
		case 'c':
			cvalue = optarg;
			strcpy(args.arg[3],cvalue);
			break;
		case 'p':
			count++;
			cvalue = optarg;
			strcpy(args.arg[2],cvalue);
			break;
		case 'h':
			help(0);
			return(0);
			break;
		case '?':
			if (optopt == 'c')
				fprintf (stderr, "Option -%c requires an argument.\n", optopt);
			else if (optopt == 'p')
				fprintf (stderr, "Option -%c requires an argument.\n", optopt);
			else if (isprint (optopt))
				fprintf (stderr, "Unknown option `-%c'.\n", optopt);
			else
				fprintf (stderr,"Unknown option character `\\x%x'.\n", optopt);
			return 1;
		default:
			abort ();
	}
	printf ("\n flag = %d\n",args.flags);
	i=0;
	for (index = optind; index < argc; index++)
	{
		printf ("Non-option argument %s\n", argv[index]);
		strcpy(args.arg[i++],argv[index]);
		count++;
	}
	if(count!=4)
	{
		printf("\nNo of arguments are not proper");
		help(-1);
		return(-1);
	}
	file = fopen(args.arg[0],"r");
	if(NULL != file)
	{
		fclose(file);
	}
	else
	{
		printf("\n unable to open input file\n");
		exit(-1);
	}
	strcpy(str,args.arg[2]);
	i=0;j=0;
	while(str[i] != '\0')
	{	
		if(str[i] != '\n')
		{
			args.arg[2][j++]=str[i++];
		}
		else 
			i++;
	}
	args.arg[2][j]='\0';
	args.key_len = strlen(args.arg[2]);
	printf("\n Initially :\n");
	printf ("\n key = %s\n",args.arg[2]);
	printf ("\n key_len = %d\n",args.key_len);
	if(args.key_len<6)
	{
		printf("\n cipher key length entered is too small");
		return(-1);
	}
	output = str2md5(args.arg[2], args.key_len);
	strcpy(args.arg[2],output);
	args.key_len = strlen(args.arg[2]);
	printf("\n after md5:\n");
	printf ("\n key = %s\n",args.arg[2]);
	printf ("\n key_len = %d\n",args.key_len);
	free(output);

	for (i = 0; i < 4; i++)
	{
		printf("\n %s ",args.arg[i]);
	}
	
  	rc = syscall(__NR_xcrypt,(void*)&args);
	if (rc == 0)
		printf("syscall returned %d\n", rc);
	else
		printf("syscall returned %d (errno=%d)\n", rc, errno);

	exit(rc);

return 0;
}
