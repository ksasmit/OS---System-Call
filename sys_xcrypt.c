#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fcntl.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/crypto.h>
#include <linux/mm.h>
#include <linux/namei.h>
#include <linux/module.h> 
#include <linux/kernel.h> 
#include <linux/fs.h>
#include <asm/uaccess.h> 
#include <asm/scatterlist.h>
#include <linux/scatterlist.h>
#include <linux/syscalls.h>
#include <linux/cred.h>
//check TBC
//argument structure from user code
struct myargs{
	int key_len;
        int flags;//1 - encryption 0- decryption
        char args[4][80];//3- type of cipher 2-key 0-infile 1-outfile
};

void make_sg( struct scatterlist *sg, char *ptr, int len );
asmlinkage extern long (*sysptr)(void *arg);

void make_sg( struct scatterlist *sg, char *ptr, int len ) {
	sg->page_link = (unsigned long)virt_to_page( ptr );
	sg->offset = offset_in_page( ptr );
	sg->length = len;
}
asmlinkage long xcrypt(void *arg)
{
	int i = 0;
	//uid_t puid;
	//gid_t pgid;
	static int check_1st_time = 0;
	struct myargs *uarg = NULL;
	struct myargs *karg;
	char *ip_buf = NULL, *op_buf = NULL,*iv=NULL,*key_buf=NULL;
	mm_segment_t old_fs;
	int read_len = 0,write_len = 0;
	int ret =0;
	struct crypto_blkcipher *tfm = NULL;
	struct blkcipher_desc desc;
	struct scatterlist sg[2];
	int errno = 0,block_len=0,pad_len=0;
	int ip_file_len=0,op_file_len=0;
	struct file *ip_file_ptr = NULL, *op_file_ptr = NULL, *temp_file_ptr = NULL;
	struct dentry *tmpDentry = NULL;
	struct inode *tmpInode = NULL;
	if (arg == NULL)
	{
		printk(KERN_ALERT"\n system side received Argument invalid");
		return -EINVAL;
	}
	
	else
	{
		karg = kmalloc(sizeof(struct myargs),GFP_KERNEL);
		if (NULL == karg)
		{
			printk(KERN_ALERT"\n system side Out of memory");
			return -ENOMEM;
		}		
	    printk(KERN_ALERT"xcrypt received arg %p\n", arg);
        uarg = (struct myargs*)arg;
/*		for(i=0;i<4;i++)
		{
			if(NULL == uarg->args[i])
			{
				printk(KERN_ALERT"\n system side received Argument invalid");
				errno= -EINVAL;
				goto CLOSE_BUFFER;			
			}
		}
		ret = access_ok( VERIFY_READ, uarg->args[0], 0 );
		if( !ret ) 
		{
			printk( KERN_ALERT "paseed user pointer is inaccessible" );
			errno = -EFAULT;
			goto CLOSE_BUFFER;
		}
		ret = access_ok( VERIFY_READ, uarg->args[2], 0 );
		if( !ret ) 
		{
			printk( KERN_ALERT "paseed user pointer is inaccessible" );
			errno = -EFAULT;
			goto CLOSE_BUFFER;
		}
*/
		ret = copy_from_user(&karg->key_len,&uarg->key_len,sizeof(int));
		if( ret != 0 )
		{
			printk( KERN_ALERT "Unable to copy key len ");
			errno = ret;
			goto CLOSE_BUFFER;
		}
		ret = copy_from_user(&karg->flags,&uarg->flags,sizeof(int));
		if( ret != 0 ) 
		{
			printk( KERN_ALERT "Unable to copy flag");
			errno = ret;
			goto CLOSE_BUFFER;
		}
		if(karg->key_len <6)
		{
			printk(KERN_ALERT"\n system side received Argument invalid");
			errno= -EINVAL;
			goto CLOSE_BUFFER;
		}
		if(!(karg->flags ==0 || karg->flags ==1))
		{
			printk(KERN_ALERT"\n system side received Argument invalid");
			errno= -EINVAL;
			goto CLOSE_BUFFER;
		}	
		key_buf = kmalloc( karg->key_len, GFP_KERNEL );
		if (NULL == key_buf)
		{
			printk(KERN_ALERT"\n system side Out of memory");
			errno = -ENOMEM;
			goto CLOSE_BUFFER;
		}
/*		if(strlen_user(uarg->args[2]) != karg->key_len)
		{
			printk(KERN_ALERT"\n system side received key size invalid");
			errno= -EINVAL;
			goto CLOSE_BUFFER;
		}
*/
		//strcpy(key_buf,"1234567890123456");
		printk(KERN_ALERT"\nkarg->key_len = %d \n",karg->key_len);
        printk(KERN_ALERT"\nkarg->flags= %d \n",karg->flags);
		for(i=0;i<4;i++)
		{
			ret = strncpy_from_user(karg->args[i],uarg->args[i],strlen_user(uarg->args[i]));//copy_from_user()
			if( ret < 0 ) 
			{
				printk( KERN_ALERT "Unable to copy arg");
				errno = ret;
				goto CLOSE_BUFFER;
			}
			printk(KERN_ALERT"\n arg %d =  %s",i,karg->args[i]);
		}
		ip_file_len = strlen_user(karg->args[0]);
		op_file_len = strlen_user(karg->args[1]);
		ret = strncpy_from_user( key_buf,uarg->args[2], karg->key_len );//copy from user
		if( ret < 0 ) {
		printk( KERN_ALERT "Unable to copy key to key buffer");
			errno = ret;
			goto CLOSE_BUFFER;
		}
		ip_file_ptr = filp_open( karg->args[0], O_RDONLY, 0 );
        if ( !ip_file_ptr || IS_ERR( ip_file_ptr ) ) 
		{
			errno = (int)PTR_ERR( ip_file_ptr );
			printk( KERN_ALERT "Error opening i/p file: %d\n", errno );
			ip_file_ptr = NULL;
			goto CLOSE_BUFFER;
    	}
/*		if(!S_ISREG( ip_file_ptr->f_path.dentry->d_inode->i_mode)) 
		{
			printk( KERN_ALERT "Input file is not regular" );
			errno = -EBADF;
			goto CLOSE_BUFFER;
		}

		if (current->real_cred->uid != ip_file_ptr->f_path.dentry->d_inode->i_uid)
		{
			printk( KERN_ALERT "owner of file and process are not same" );
			errno = -EACCES;
			goto CLOSE_BUFFER;
		}*/
		op_file_ptr = filp_open( karg->args[1], O_WRONLY | O_CREAT,0);
        if ( !op_file_ptr || IS_ERR( op_file_ptr ) ) 
		{
			errno = (int)PTR_ERR( op_file_ptr );
			printk( KERN_ALERT "Error opening o/p file: %d\n", errno );
			op_file_ptr = NULL;
			goto CLOSE_BUFFER;
        }
/*		if(( ip_file_ptr->f_path.dentry->d_inode->i_sb == op_file_ptr->f_path.dentry->d_inode->i_sb ) && // superblock
			(ip_file_ptr->f_path.dentry->d_inode->i_ino ==  op_file_ptr->f_path.dentry->d_inode->i_ino )) //inode no
		{
			printk( KERN_ALERT "input and output files have same inode and are in the same superblock" );
			errno = -EINVAL;
			goto CLOSE_BUFFER;
		}
*/
// Set the o/p file permission to i/p file and process
		//pgid = getgid();
		//printk("The real GID is: %u\n", pgid);
		op_file_ptr->f_path.dentry->d_inode->i_mode =  ip_file_ptr->f_path.dentry->d_inode->i_mode;
//		op_file_ptr->f_path.dentry->d_inode->i_uid = current->real_cred->uid;
//		op_file_ptr->f_path.dentry->d_inode->i_gid = current->real_cred->gid;
// Set the file position to the beginning of the file
        ip_file_ptr->f_pos = 0;
        op_file_ptr->f_pos = 0;
// buffer to read data and write data, size equal to PAGE_SIZE 
        ip_buf = kmalloc( PAGE_SIZE, GFP_KERNEL );
        if( NULL == ip_buf ) {
            errno = -ENOMEM;
            goto CLOSE_BUFFER;
        }
        memset( ip_buf,'\0', PAGE_SIZE );
        op_buf = kmalloc( PAGE_SIZE, GFP_KERNEL );
        if( NULL == op_buf ) {
            errno = -ENOMEM;
            goto CLOSE_BUFFER;
        }
		memset( op_buf,'\0', PAGE_SIZE );
// Allocate tfm cipher scheme aes mode cbc
		tfm = crypto_alloc_blkcipher( "cbc(aes)", 0, 0 );
		if ( NULL == tfm  )
		{
			printk( KERN_ALERT "Failed to allocate tfm");
			errno = -EINVAL;
			goto CLOSE_BUFFER;
		}
// Initialize desc
		desc.tfm = tfm;
		desc.flags = 0;
		if( crypto_blkcipher_setkey( tfm, key_buf, karg->key_len )) 
		{
			printk( "crypto_blkcipher_setkey() failed");
			errno = -EINVAL;
			goto CLOSE_CIPHER;
		}

// Initialize sg structure
		make_sg( &sg[0], ip_buf, PAGE_SIZE );
		make_sg( &sg[1], op_buf, PAGE_SIZE );

// Get the block size
		block_len = ((tfm->base).__crt_alg)->cra_blocksize;

// Initialize IV
		iv = kmalloc( block_len, GFP_KERNEL );
		if( NULL == iv ) 
		{
			errno = -ENOMEM;
			goto CLOSE_CIPHER;
		}
		
		memset( iv, '\0', block_len );
		crypto_blkcipher_set_iv( tfm, iv, crypto_blkcipher_ivsize( tfm ) );

//encryption - preamble
		if(1 == karg->flags )
		{
// use a temp file to write the preambal and input file contents
			temp_file_ptr = filp_open( "temp.txt", O_WRONLY | O_CREAT,0);
			if ( !temp_file_ptr || IS_ERR( temp_file_ptr ) ) 
			{
				errno = (int)PTR_ERR( temp_file_ptr );
				printk( KERN_ALERT "Error opening temp_file file in write mode: %d\n", errno );
				temp_file_ptr = NULL;
				goto CLOSE_BUFFER;
			}
// Set the temp file permission to i/p file
			temp_file_ptr->f_path.dentry->d_inode->i_mode =  ip_file_ptr->f_path.dentry->d_inode->i_mode;
			temp_file_ptr->f_pos = 0;
			memcpy( op_buf, key_buf, karg->key_len );
			old_fs = get_fs();
			set_fs( KERNEL_DS );
			write_len = temp_file_ptr->f_op->write( temp_file_ptr, op_buf,karg->key_len, &temp_file_ptr->f_pos );
			set_fs(old_fs);
			while( ip_file_ptr->f_pos < ip_file_ptr->f_path.dentry->d_inode->i_size )
			{
				memset( ip_buf,'\0', PAGE_SIZE );
				old_fs = get_fs();
				set_fs( KERNEL_DS );
				read_len = ip_file_ptr->f_op->read( ip_file_ptr, ip_buf, PAGE_SIZE, &ip_file_ptr->f_pos );
				//read_len--;//TBC
				set_fs( old_fs );
				old_fs = get_fs();
				set_fs( KERNEL_DS );
				write_len = temp_file_ptr->f_op->write( temp_file_ptr, ip_buf, read_len, &temp_file_ptr->f_pos );
				set_fs( old_fs );
			}//end of temp file writing
			temp_file_ptr->f_pos = 0;
			ip_file_ptr->f_pos = 0;
			memset( ip_buf,'\0', PAGE_SIZE );
			memset( op_buf,'\0', PAGE_SIZE );
			if( temp_file_ptr ) 
			{
				filp_close( temp_file_ptr, NULL );
				temp_file_ptr = NULL;
				printk( KERN_ALERT "temp file closed" );
			}
			temp_file_ptr = filp_open( "temp.txt", O_RDONLY, 0 );
			if ( !temp_file_ptr || IS_ERR( temp_file_ptr ) ) 
			{
				errno = (int)PTR_ERR( temp_file_ptr );
				printk( KERN_ALERT "Error opening temp file in read mode: %d\n", errno );
				temp_file_ptr = NULL;
				goto CLOSE_BUFFER;
			}
			temp_file_ptr->f_pos = 0;	
		}
		else if(0 == karg->flags )//decryption- for preamble
		{
			printk("\ndecrypt do nothing");
			temp_file_ptr = ip_file_ptr;
			ip_file_ptr->f_pos = 0;
		}
//enc dec below
        while( temp_file_ptr->f_pos < temp_file_ptr->f_path.dentry->d_inode->i_size ) 
		{
			memset( ip_buf,'\0', PAGE_SIZE );
			memset( op_buf,'\0', PAGE_SIZE );

			old_fs = get_fs();
			set_fs( KERNEL_DS );

			read_len = temp_file_ptr->f_op->read( temp_file_ptr, ip_buf, PAGE_SIZE, &temp_file_ptr->f_pos );
			//read_len--;//fix

			set_fs( old_fs );
			//printk(KERN_INFO "\n input buf:%s\n",ip_buf);
			//memcpy( op_buf, ip_buf, read_len );
			switch( karg->flags ) 
			{
				case 1:
					printk( KERN_ALERT "Bytes read from I/P file =%d\n", read_len );
					if( read_len % block_len > 0 ) 
					{
						pad_len = block_len - ( read_len % block_len );
						memset( ip_buf + read_len, ':', pad_len );
						read_len += pad_len;
					}
					printk( KERN_ALERT "Pad Length =%d\n", pad_len );
					printk( KERN_ALERT "Data read from I/P file =%s\n", ip_buf );
// Encrypt the data
					if (crypto_blkcipher_encrypt( &desc, &sg[1], &sg[0], PAGE_SIZE )) 
					{
						printk( KERN_ALERT "Encryption failed. karg.flags=0x%x\n", tfm->base.crt_flags );
						op_file_ptr = filp_open( karg->args[1], O_WRONLY , 0 );
						if ( !op_file_ptr || IS_ERR( op_file_ptr ) )
						{
							errno = (int)PTR_ERR( op_file_ptr );
							op_file_ptr = NULL;
						}
						else
						{
							tmpDentry = op_file_ptr->f_path.dentry;
							tmpInode = tmpDentry->d_parent->d_inode;

							filp_close( op_file_ptr, NULL );
							vfs_unlink( tmpInode, tmpDentry,NULL);
							printk( KERN_ALERT "O/p file deleted ..." );
						}
						goto CLOSE_IV;
					}

					break;

				case 0:
// Decrypt the data
					printk( KERN_ALERT "Decryption case entry");
					memset( op_buf,'\0', PAGE_SIZE );
					if (crypto_blkcipher_decrypt( &desc, &sg[1], &sg[0], PAGE_SIZE ))
					{
						printk( KERN_ALERT "Decryption failed. karg.flags=0x%x\n", tfm->base.crt_flags );
						op_file_ptr = filp_open( karg->args[1], O_WRONLY , 0 );
						if ( !op_file_ptr || IS_ERR( op_file_ptr ) )
						{
							errno = (int)PTR_ERR( op_file_ptr );
							op_file_ptr = NULL;
						}
						else
						{
							tmpDentry = op_file_ptr->f_path.dentry;
							tmpInode = tmpDentry->d_parent->d_inode;
							filp_close( op_file_ptr, NULL );
							vfs_unlink( tmpInode, tmpDentry,NULL);
							printk( KERN_ALERT "O/p file deleted" );
						}
						goto CLOSE_IV;
					}
					printk( KERN_ALERT "Bytes read from I/P file =%d=\n", read_len );
					//read_len-=1;//fix
					while( op_buf[read_len - 1] ==':' ) 
					{
						op_buf[ read_len - 1 ] = '\0';
						read_len-=1 ;
					}
					printk( KERN_ALERT "Bytes read from I/P file =%d\n", read_len );
					printk( KERN_ALERT "Data read from I/P file =%s\n", op_buf );

// for preamble key check
					if(0==check_1st_time)
					{
						for(i=0;i < karg->key_len;i++)
						{
							if(op_buf[i]!= key_buf[i])
							{
								errno = -EINVAL;
								printk( KERN_ALERT "preamble not matching for decryption");
								goto CLOSE_IV;
							}
						}
					}
				break;
			}
//enc dec ends		
// Start writing to the o/p file
			old_fs = get_fs();
			set_fs( KERNEL_DS );
			if(1 == karg->flags )
				write_len = op_file_ptr->f_op->write( op_file_ptr, op_buf, read_len, &op_file_ptr->f_pos );
			else if(0 == karg->flags && 0==check_1st_time)
			{
				write_len = op_file_ptr->f_op->write( op_file_ptr, op_buf + karg->key_len, read_len- karg->key_len, &op_file_ptr->f_pos );
				check_1st_time = 1;
			}
			else if(0 == karg->flags && 0!=check_1st_time)
				write_len = op_file_ptr->f_op->write( op_file_ptr, op_buf, read_len, &op_file_ptr->f_pos );
			set_fs( old_fs );
        }//end of while
		if(0 == karg->flags)
		{
			temp_file_ptr = NULL;
		}
	}// end of else
CLOSE_IV:
	kfree( iv );
	printk( KERN_ALERT "Memory for IV freed ..." );

CLOSE_CIPHER:
	crypto_free_blkcipher( tfm );
	printk( KERN_ALERT "Encryption Transform freed ..." );

CLOSE_BUFFER:
	if( ip_buf ) 
	{
		kfree( ip_buf );
	}

	if( op_buf ) 
	{
		kfree( op_buf );
	}
	if( key_buf ) 
	{
		kfree( key_buf );
	}
	if( karg ) 
	{
		kfree( karg );
	}
	printk( KERN_ALERT "Memory for buffers freed" );

//CLOSE_FILE:
	if( ip_file_ptr ) 
	{
		filp_close( ip_file_ptr, NULL );
		ip_file_ptr = NULL;
		printk( KERN_ALERT "I/p file closed" );
	}

	if( op_file_ptr ) 
	{
		filp_close( op_file_ptr, NULL );
		op_file_ptr = NULL;
		printk( KERN_ALERT "O/p file closed" );
	}
	if( temp_file_ptr ) 
	{
		filp_close( temp_file_ptr, NULL );
		tmpDentry = temp_file_ptr->f_path.dentry;
		temp_file_ptr = NULL;
		printk( KERN_ALERT "temp file closed" );
		tmpInode = tmpDentry->d_parent->d_inode;
		vfs_unlink( tmpInode, tmpDentry,NULL);
		printk( KERN_ALERT "temp file deleted " );
	}
return errno;
}

static int __init init_sys_xcrypt(void)
{
	printk(KERN_ALERT"installed new sys_xcrypt module\n");
	if (sysptr == NULL)
		sysptr = xcrypt;
	return 0;
}
static void  __exit exit_sys_xcrypt(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk(KERN_ALERT"removed sys_xcrypt module\n");
}
module_init(init_sys_xcrypt);
module_exit(exit_sys_xcrypt);
MODULE_LICENSE("GPL");

