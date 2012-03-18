/*  
 *  sys_xcrypt.c - Provides implementation for sys_xcrypt
 *
 *  Description : Module for xcipher encryption support
 *  
 *  Author : Jaison George <jaisong87@gmail.com>
 */
#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/init.h>		/* Needed for the macros */
#include <linux/slab.h>
#include <asm/uaccess.h>        /* Needed for checks before read/write */
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include<linux/crypto.h>
#include "xcryptUtils.h" /* xcrypt structures and definitions */

/* This file contains the implementation of xcrypt system call and encryption/decryption
 * functions for encryption/decryption operations on the file
 * Initializing the module will register xcryptImpl 
 */

#define MOD_AUTHOR "Jaison George"
#define MOD_DESCR "Xcrypt - Encryption utility for file systems"

MODULE_LICENSE("GPL");
MODULE_AUTHOR(MOD_AUTHOR);
MODULE_DESCRIPTION(MOD_DESCR);


extern long (*xcryptImpl)(void *args);
static const u8 *aes_iv = (u8 *)"abcdefghijklmnop"; /* Default IV */

static int xcrypt_aes_encrypt(const void *key, int key_len, void *dst, size_t *dst_len, const void *src, size_t src_len);
static int xcrypt_aes_decrypt(const void *key, int key_len, void *dst, size_t *dst_len, const void *src, size_t src_len, int check_for_paddding);


int enc_dec_file(const char* , const char*, int , char*); 

/**
 * myXcryptImpl - Implementation for the xcrypt system call
 *
 * @args:   Pointer to xcryptParams(struct) that contains all the information
 *
 * This is the implementation for xcrypt system call. It calls
 * appropriate helper utilities to accomplish the encryption/decryption task.
 */
long myXcryptImpl(void *args)
{
struct xcryptParams* xcryptArgs_user_space;
struct xcryptParams* xcryptArgs;
int xcrypt_ret_val, pending_copy_len;

xcryptArgs_user_space = (struct xcryptParams*)args;
xcryptArgs = kmalloc(sizeof(struct xcryptParams), GFP_KERNEL);
xcrypt_ret_val = 0;

	/* Allocate memory for xcryptArgs Structure 
	 * Throw ENOMEM if needed
	 */		
	if(NULL == xcryptArgs)	
		{
		xcrypt_ret_val = -ENOMEM;
		printk(KERN_ERR "Xcrypt Module : Unable to allocate memory for xcyptArgs\n");
		goto XCRYPT_NO_CLEANUP; 			
		}
	
	/* Ensure that memCopy to kernel Space is fine - Do not trust userspace. This could be a wild pointer  
	 * Check for validiaty and also check if copying succeeded
	 */
        pending_copy_len = copy_from_user( xcryptArgs , xcryptArgs_user_space , sizeof(struct xcryptParams));
	if(pending_copy_len != 0 )
		{
		xcrypt_ret_val = -EFAULT;
		printk(KERN_ERR "Xcrypt Module :Error in copying args(%d bytes remaining from %d)\n", pending_copy_len, sizeof(struct xcryptParams));
		goto XCRYPT_CLEAN_UP_BUFFER; 
		}
	
	/* Check for file-names - Basic check on fileName */

	if( (NULL == xcryptArgs->infile) || ( NULL == xcryptArgs->outfile) )
	{
		xcrypt_ret_val = -EINVAL; 	
		goto XCRYPT_CLEAN_UP_BUFFER;		
	}

	/* Encrypt/Decrypt the File */
	printk(KERN_INFO "Xcrypt - Encrypting/Decrypting %s into %s using key : %s\n", xcryptArgs->infile, xcryptArgs->outfile,xcryptArgs->encKey);
	xcrypt_ret_val = enc_dec_file(xcryptArgs->infile, xcryptArgs->outfile, xcryptArgs->doEncrypt, xcryptArgs->encKey);	

	
	XCRYPT_CLEAN_UP_BUFFER:
        /* Free all the buffers here  */
        kfree(xcryptArgs);

	XCRYPT_NO_CLEANUP: 
	/* If the first kmalloc fails, we jump here */

printk(KERN_INFO "myXcryptImpl : Operation completed with ret_val %d\n", xcrypt_ret_val);
return xcrypt_ret_val;
}

/*  Initialize the module and register xcyptImpl with the kernel
 */
static int __init hello_2_init(void)
{
	xcryptImpl = &myXcryptImpl;
	printk(KERN_INFO " Xcrypt Module Loaded - Registered the implementation with kernel\n");
	return 0;
}

/* Removes the module and cleanly reset xcryptImpl to NULL
 */
static void __exit hello_2_exit(void)
{
	xcryptImpl = NULL;
	printk(KERN_INFO "Xcrypt Module Removed - Removing the implementation from kernel \n");
}

/* enc_dec_file - Performs appropriate encrypt/decrypt operation depending on the arguments
 * The function performs cbc(aes) on encKey using encKey as the key and this is written to 
 * outfile. outFile is written in blocks of size block_size which is set to be PAGE_SIZE
 *
 * @param inFile - Input File
 * @param outFile - Output File
 * @doEncrypt - Flag specifying the operation type(encrypt/decrypt)
 * @encKey - Key for encryption/decryption
 */
int enc_dec_file(const char *inFile, const char *outFile, int doEncrypt, char * encKey)
{
	/* Variable declerations*/	
        struct file *rfilp,*wfilp;
        mm_segment_t oldfs;
        int rbytes, wbytes, read_size, write_size, block_size;	
        long rfile_size;
	
        int no_blocks_in_input_file;  	/*total number of FULL blocks in input file */ 
        int residue_size;             	/*the residue bytes in the last block which may not be full */
        int i;                       	/*used for for loop */
	int ret_val; 			/* Default return value is Success */
	char* decKey;
	struct inode * outfile_inode;
	struct dentry * outfile_dentry;	
	int output_file_created;	
	
	void * buf,*wbuf; /* read and write buffers on file blocks */	

	/* Initialize variables */
	rbytes = 0;
	wbytes = 0;
	read_size = 0;
	write_size = 0;		
	rfile_size = 0;	
	ret_val = 0; /* Success by default */	
	i = 0;

	wfilp = NULL;
	rfilp = NULL;	
	outfile_inode = NULL;
	outfile_dentry = NULL;	
	output_file_created = 0 ; /* Output File is not created by the function ( required to determine file removal cleanup action )*/	
	decKey = kmalloc(17, GFP_KERNEL);
	buf = NULL;
	wbuf = NULL;

	/* Allocate buffer for DecKey */
	 if(NULL == decKey)
                { 
                ret_val = -ENOMEM;
                goto ENC_NO_CLEANUP;
                }	
	
	/* Allocate Write Buffer with size of PAGE_SIZE */
        wbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if(NULL == wbuf)
		{	
		ret_val = -ENOMEM;
		goto ENC_CLEANUP_KEYBUF;
		}

	/* Allocate read buffer with size of block size */
	buf  = kmalloc(PAGE_SIZE, GFP_KERNEL);	
	if(NULL == buf)
		{
		ret_val = -ENOMEM;
		goto ENC_CLEANUP_WBUF;
		}
	
        //READ FILE
        /* Try to open input File and read is permitted */
        rfilp = filp_open(inFile, O_RDONLY|O_LARGEFILE , 0);
        if (!rfilp || IS_ERR(rfilp)) {
          printk(KERN_ERR "XCRYPT MODULE ERROR : File Read error %d on %s\n", (int) PTR_ERR(rfilp), inFile);
          ret_val = -ENOENT;  /* or do something else */
	  goto ENC_CLEANUP_BUFFERS;	 
        }

        if (!rfilp->f_op->read)
		{
          printk(KERN_ERR "XCRYPT MODULE ERROR : File system doesn't allow read %d on %s\n", (int) PTR_ERR(rfilp), inFile);
          ret_val = -EIO;  /* file(system) doesn't allow reads */
	  goto ENC_CLEANUP_BUFFERS;	 
		}

        //WRITE FILE
        /*Check if outpout File Exists */	
	wfilp = filp_open(outFile, O_RDONLY|O_LARGEFILE, 0);
	if(!wfilp || IS_ERR(wfilp) ); /* File should not open */
	else	{
          printk(KERN_ERR "XCRYPT MODULE ERROR : Output File %s already exists %d \n", outFile,  (int) PTR_ERR(wfilp));	
		return -EEXIST;
		}
		

        /* Try creating the output File */
        wfilp = filp_open(outFile, O_CREAT | O_WRONLY|O_LARGEFILE, rfilp->f_mode);
        if (!wfilp || IS_ERR(wfilp)) {
          printk(KERN_ERR "XCRYPT MODULE ERROR : File Create/Write error %d on %s\n", (int) PTR_ERR(wfilp),outFile);
          ret_val = -ENOENT;  /* or do something else */
	  goto ENC_CLEANUP_RFD; 
        }
		
	 /* Mark the flag output_file_created as true and get its dentry */ 
	 output_file_created = 1;
         outfile_dentry = wfilp->f_dentry;
	
	 /* Check if we are able to write to output File */
	 if (!wfilp->f_op->write)
          		{
         printk(KERN_ERR "XCRYPT MODULE ERROR : File system doesn't allow write %d on %s\n", (int) PTR_ERR(rfilp), outFile);
       	 ret_val = -EROFS;  /* file(system) doesn't allow writes */
	 goto ENC_CLEANUP_FDS; 	
			}
		
	/* Copy ownership and permissions */
	wfilp->f_dentry->d_inode->i_mode = rfilp->f_dentry->d_inode->i_mode;
	wfilp->f_dentry->d_inode->i_opflags = rfilp->f_dentry->d_inode->i_opflags;
	wfilp->f_dentry->d_inode->i_uid = rfilp->f_dentry->d_inode->i_uid;
	wfilp->f_dentry->d_inode->i_gid = rfilp->f_dentry->d_inode->i_gid;
	wfilp->f_dentry->d_inode->i_flags = rfilp->f_dentry->d_inode->i_flags;

	/* Count the blocks and calculate the residue on last block */	
        rfile_size = rfilp->f_dentry->d_inode->i_size;
        no_blocks_in_input_file = rfile_size/PAGE_SIZE;
        residue_size = rfile_size%PAGE_SIZE;

        /* now start reading block_size bytes starting from offset 0 */
        rfilp->f_pos = 0;               /* start offset */
        oldfs = get_fs();
        set_fs(KERNEL_DS);
        wfilp->f_pos=0;

        printk(KERN_INFO "XCRYPT MODULE : inpFileSize %ld , blockCount : %u  Residue : %u\n", rfile_size, no_blocks_in_input_file, residue_size );
        printk(KERN_INFO "XCRYPT MODULE : Writing Files with block-size of %lu \n", PAGE_SIZE);
	
	/* Copy the 128-bit encryptionKey and encrypt it and use this key*/
	memcpy(buf, encKey,16);
	block_size = 16; /* Encrypting Key-Phrase using cbc(aes) and key is itself */
	ret_val = xcrypt_aes_encrypt(buf, 16, decKey , &block_size , encKey , block_size );

	printk(KERN_INFO " decKey is %s\n",decKey);	
	
	block_size = PAGE_SIZE; /* We always deal in currency of BLOCK_SIZE except for the last block */
	i = 0;

       /* Write the Preamble using salted-key*/
	if( ENCRYPT_OPT_DO_ENCRYPT == doEncrypt)
	{
		memset(wbuf, block_size, 0);
		memcpy(wbuf, decKey, 16);	
		write_size = wfilp->f_op->write(wfilp, wbuf, block_size, &wfilp->f_pos);
                wbytes += write_size;
	} 
	/* Read the Preamble to cross-check salted-key*/
	else if( ENCRYPT_OPT_DO_DECRYPT == doEncrypt)
	{
	       read_size = rfilp->f_op->read(rfilp, buf, PAGE_SIZE, &rfilp->f_pos);
	       if(read_size != block_size)
	       {
		       printk(KERN_INFO "XCRYPT MODULE ERROR : Could read only %d  bytes out of %d required\n", read_size, block_size );
		       ret_val = -EIO;
	       }

               rbytes += read_size;
	       i++;
	       if(0 == memcmp(decKey, buf,16))
			{
			printk(KERN_INFO "Successfully validated the key\n");
			}
		else { 
			ret_val = -EKEYREJECTED;
         		printk(KERN_ERR "XCRYPT MODULE ERROR : Invalid Key!\n");
			}
	}

       /* Write blocks in units of PAGE_SIZE in a loop*/	
       for( ;(i < no_blocks_in_input_file) && (0 == ret_val);i++) {
		
		/* read from input file */
	       read_size = rfilp->f_op->read(rfilp, buf, PAGE_SIZE, &rfilp->f_pos);
	       rbytes += read_size;
		if(read_size != block_size)
		{
         		printk(KERN_INFO "XCRYPT MODULE ERROR : Could read only %d  bytes out of %d required\n", read_size, block_size );
			ret_val = -EIO;
		}

		/* encrypt/decrypt depending on the option specified */		
	       if( ENCRYPT_OPT_DO_ENCRYPT == doEncrypt)
	       {
		     ret_val = xcrypt_aes_encrypt(decKey, 16, wbuf , &block_size , buf , block_size );
		     /* printk(KERN_INFO "Encrypting block#%i\n",i);  Uncomment this line for debugging */
	       } 
	       else if( ENCRYPT_OPT_DO_DECRYPT == doEncrypt)
	       { 
		     ret_val = xcrypt_aes_decrypt(decKey, 16, wbuf , &block_size , buf , block_size, 0 );
		     /* printk(KERN_INFO "Decrypting block#%i\n",i);  Uncomment this line for debugging */
	       }
	       else {
		       printk(KERN_ERR "XCRYPT MODULE ERROR : Unknown Operation\n");
		       ret_val = -EINVAL;
	       }
         
		/* write to output-file */
	       write_size = wfilp->f_op->write(wfilp, wbuf, block_size, &wfilp->f_pos);
	       wbytes += write_size;
		if(write_size != block_size)
			{
			ret_val = -EIO;	
         		printk(KERN_INFO "XCRYPT MODULE ERROR : Could write only %d  bytes out of %d required\n", write_size, block_size );
			}
       }

	if(ret_val != 0 )
		goto ENC_CLEANUP_ALL;

	/* All complete blocks are over 
         * There is one block pending with residue_size bytes
         */
	read_size = rfilp->f_op->read(rfilp, buf, residue_size, &rfilp->f_pos);
	if(read_size != residue_size) { 
		ret_val = -EIO;
         	printk(KERN_ERR "XCRYPT MODULE ERROR : Could read only %d  bytes out of %d required\n", read_size, residue_size );
		goto ENC_CLEANUP_ALL;
	}

	rbytes += read_size;		
	
	/* Write the residue to output */		
	if( ENCRYPT_OPT_DO_ENCRYPT == doEncrypt)
	{	
	ret_val = xcrypt_aes_encrypt(decKey, 16, wbuf , &residue_size , buf , residue_size );
	}
	else if( ENCRYPT_OPT_DO_DECRYPT == doEncrypt)
	{
	ret_val = xcrypt_aes_decrypt(decKey, 16, wbuf , &residue_size , buf , residue_size, 1 );	
	}
	else {
	printk(KERN_ERR "XCRYPT MODULE ERROR : Unknown Operation\n");	
	ret_val = -EINVAL;
	}

        wbytes += wfilp->f_op->write(wfilp, wbuf, residue_size, &wfilp->f_pos);

	/* finished writing to outputFile - Release the resources now*/
	ENC_CLEANUP_ALL:
        set_fs(oldfs);
	printk(KERN_INFO "XCRYPT MODULE SUCCESS : Wrote %d Bytes out of %d Bytes from %s to %s\n", wbytes, rbytes, inFile, outFile );
	if( (wbytes < rbytes ) &&(1 == doEncrypt ) ) /* While encrypting written bytes would be at-leat read bytes */
		{
			ret_val = -EIO;
         		printk(KERN_INFO "XCRYPT MODULE ERROR : Read Bytes of %d mismatch with written bytes of %d for this operation\n", rbytes, wbytes );
		}	
	if( (wbytes > rbytes ) && (0 == doEncrypt) ) /* while decryting written bytes would be at most read bytes */
		{	
			ret_val = -EIO;
         		printk(KERN_INFO "XCRYPT MODULE ERROR : Read Bytes of %d mismatch with written bytes of %d for this operation\n", rbytes, wbytes );
		}
	  /* close the file */
	ENC_CLEANUP_FDS:
        filp_close(wfilp, NULL);
	
	ENC_CLEANUP_RFD:
        filp_close(rfilp, NULL);

	ENC_CLEANUP_BUFFERS:
        kfree(buf);

       	ENC_CLEANUP_WBUF: 
	kfree(wbuf);

        ENC_CLEANUP_KEYBUF: 
	kfree(decKey);	

	ENC_NO_CLEANUP:
	printk(KERN_INFO "XCRYPT MODULE SUCCESS : Closed Files and Freed Resources\n");
	
	/* In case of failure and if temporary file was created, remove it */
	if( 1 == output_file_created  && ret_val != 0 )        
	{
		printk(KERN_INFO "XCRYPT MODULE CLEANUP : Removing temporary File\n");
		vfs_unlink( outfile_dentry->d_parent->d_inode , outfile_dentry);	
	}

	return ret_val;
}

/* xcrypt_aes_encrypt - Perform aes decryption on src using key and dumps the output to dst
 * In case of bad padding, error is returned. 
 *
 * @param - key ( Key for encryption[Typically 128-bit for xcrypt] )
 * @param - key ( length of the  Key for decryption )
 * @param - src ( source buffer )
 * @param - src_len ( length of the source buffer for encryption )
 * @param - dst ( destionation buffer - to be filled after after decrypting )
 * @param - dst_len ( length of the destination buffer )
 */
static int xcrypt_aes_encrypt(const void *key, int key_len,
                            void *dst, size_t *dst_len,
                            const void *src, size_t src_len)
{
        struct scatterlist sg_in[2], sg_out[1];
        struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("cbc(aes)", 0, CRYPTO_ALG_ASYNC);
        struct blkcipher_desc desc = { .tfm = tfm, .flags = 0 };
        int ret;
        void *iv;
        int ivsize;
	//size_t aes_residue = (src_len & 0x0f);
        char pad[16];
        size_t zero_padding = (0x10 - (src_len & 0x0f))%16;

	/*
	if(aes_residue) {
		zero_padding = 0x10 - aes_residue;
			}
	*/

        if (IS_ERR(tfm))
                return PTR_ERR(tfm);

        memset(pad, zero_padding, zero_padding);

        *dst_len = src_len + zero_padding;

        crypto_blkcipher_setkey((void *)tfm, key, key_len);
        sg_init_table(sg_in, 2);
        sg_set_buf(&sg_in[0], src, src_len);
        sg_set_buf(&sg_in[1], pad, zero_padding);
        sg_init_table(sg_out, 1);
        sg_set_buf(sg_out, dst, *dst_len);
        iv = crypto_blkcipher_crt(tfm)->iv;
        ivsize = crypto_blkcipher_ivsize(tfm);

        memcpy(iv, aes_iv, ivsize);
	ret = crypto_blkcipher_encrypt(&desc, sg_out, sg_in,
                                     src_len + zero_padding);
        crypto_free_blkcipher(tfm);
        if (ret < 0)
		{
                printk(KERN_INFO "Xcrypt Module : AES_encrypt failed %d\n", ret);
		
        	}

               	printk(KERN_INFO "Xcrypt Module : AES_encrypt success %d\n", ret);
	return 0;
}

/* xcrypt_aes_decrypt - Perform aes decryption on src using key and dumps the output to dst
 * In case of bad padding, error is returned. 
 *
 * @param - key ( Key for encryption[Typically 128-bit for xcrypt] )
 * @param - key ( length of the  Key for decryption )
 * @param - src ( source buffer )
 * @param - src_len ( length of the source buffer for encryption )
 * @param - dst ( destionation buffer - to be filled after after decrypting )
 * @param - dst_len ( length of the destination buffer )
 */
static int xcrypt_aes_decrypt(const void *key, int key_len,
                            void *dst, size_t *dst_len,
                            const void *src, size_t src_len, int check_for_padding)
{
	/* Variable declerations */
        struct scatterlist sg_in[1], sg_out[2];
        struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("cbc(aes)", 0, CRYPTO_ALG_ASYNC);
        struct blkcipher_desc desc = { .tfm = tfm };
        char pad[16];
        void *iv;
        int ivsize;
        int ret;
        int last_byte;

        if (IS_ERR(tfm))
                return PTR_ERR(tfm);
	
	/* Initialize values */
        crypto_blkcipher_setkey((void *)tfm, key, key_len);
        sg_init_table(sg_in, 1);
        sg_init_table(sg_out, 2);
        sg_set_buf(sg_in, src, src_len);
        sg_set_buf(&sg_out[0], dst, *dst_len);
        sg_set_buf(&sg_out[1], pad, sizeof(pad));

        iv = crypto_blkcipher_crt(tfm)->iv;
        ivsize = crypto_blkcipher_ivsize(tfm);

        memcpy(iv, aes_iv, ivsize);
	
	/* Decrypt the block */
     	ret = crypto_blkcipher_decrypt(&desc, sg_out, sg_in, src_len);
        crypto_free_blkcipher(tfm);
        if (ret < 0) {
                printk(KERN_INFO "Xcrypt Module : AES_decrypt failed %d\n", ret);
                return ret;
        }

	/* We need to check for padding only on the last block of the File 
	 * For the last block, call is made using check_for_padding = 1 
         */
	if(1 == check_for_padding)
	{
		printk(KERN_INFO "Xcrypt Module : Checking the block for padding \n");
		if (src_len <= *dst_len)
			last_byte = ((char *)dst)[src_len - 1];
		else
			last_byte = pad[src_len - *dst_len - 1];
		if (last_byte <= 16 && src_len >= last_byte) {
			*dst_len = src_len - last_byte;
		} else {
			printk(KERN_ERR "Xcrypt Module : xcrypt_aes_decrypt got bad padding %d on src len %d\n",
					last_byte, (int)src_len);
			return -EILSEQ;  /* bad padding */
		}
	} 
        return 0; /* Successfully completed Decryption */
}

module_init(hello_2_init);
module_exit(hello_2_exit);

