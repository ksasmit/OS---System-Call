									Name - Kumar Sasmit
									SBU ID: 110308698


I have implemented almost all the basic requirements as mentioned in HW1.txt sheet.
I have used AES encryption with Cipher Block Chaining (CBC) mode in my work.


On the User side
	I have made xcipher.c for user space execution.
	When executed user has to enter the command as required
	/xcipher -<e/d> -c <cipher type> -p "<key>" <infile> <outfile> [-h for help]
	user can enter the arguments in any order, 
	It is required that the outfile name should come after input file 
	and there should be a string entry after -p,-c option, other wise an error is thrown with help menu displayed.
	I have made some necessary check like,
		the no. of argument which are necessary to be entered.
		If input file is opening in read mode
		Removing '\n' characters from the key
		The size of key length entered.
	After that the key is hashed by MD5 hask method, and the new key and key length are updated
	The system call is made with a single void pointer argument pointing to the address of structure containing the arguments to be passed is stored in the user space.

on the system side:
arguments are read and stored in a structure on kernel side similar as that on the user side
First of all following checks are made
	- missing arguments passed
	- null arguments
	- pointers to bad addresses
	- len and buf don't match
	- invalid flags
	- input file cannot be opened or read
	- output file cannot be opened or written
	- input or output files are not regular, or they point to the same file
	- trying to decrypt a file w/ the wrong key 
	any non matching condition/failure is returning the appropriate error message
	the protection mode of output file has been made same as that of input file
	I have used Synchronous Block Cipher Apis for the entire module
	For preamble part I have used another temporary file.I appended the hashed key received from user space on the temp file as preamble followed by entire content on input file.After that when encrypting, the temp file is being taken as the input file,
	While encrypting the preamble along with the contents are being read - encrypted and written on the output file.
	Each read and write is happening in chunks, each read chunk at max equals to the Page size.The encryption happens in the order of blocks.The read characters are encrypted If the characters in last block is smaller than the max block  size , it is padded with ':' characters. Therefore the output file after encryption contains encrypted preamble followed by encrypted file contents and encrypted ':' characters.
	While decrypting the encrypted file is read in the chunk of page size and decryption is done.For the first time after decryption first n characters(no. = key length) are compared with that passed by the user.If they dont match,decryption is terminated with error message.If all goes well, the entire encrypted file is decrypted and written on the output file, removing the preamble from the front and decrypted padded ':' characters from the end. 
	Temporary file is deleted and all buffers freed before the return.

I have made some changes in makefile for linking crypto and ssl modules

Extra Credits:

I have used IV - initialization vector while setting key.

Here are the list of stuffs which I could not do:
1. The output file should be created with the user/group ownership of the running process. - I tried but it was causing kernel panic.
2. partial write failure - I could not try vfs_rename().