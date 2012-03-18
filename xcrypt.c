/***************************************************
 * 
 * Xcipher - File encryption Utility using sys_xcrypt
 *
 * Description - A command line utility for encrypting 
 * files on Linux systems.
 *
 * Author - Jaison George <jaisong87@gmail.com>
 *
 **************************************************/
#include <stdio.h>
#include <linux/unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include "xcryptUtils.h"
#include <openssl/md5.h>

void print_usage()
{
printf("Usage: xcipher [ OPTIONS ] SOURCE DESTINATION\n");
printf("Encrypts/Decrypts SOURCE to DESTINATION using the specified key \n");
printf("Mandatory arguments \n");
printf(" -e  Encrypt source to destination\n");
printf(" -d  Decrypt source to destination\n");
printf(" -p  <passphrase> Encrypt using the specified passphrase\n");
return;
}

int main(int argc, char *argv[])
{
  struct xcryptParams xcryptArgs = { ENCRYPT_OPT_UNKNOWN /*Encrypt or Decrypt*/, "AES" /*Default Type if AES*/ , "abcdefgh12345678" /*Default Key*/, 0/*keylen*/ ,"" /*No infile*/,""/*No outFile*/ }; /*Initialize xcrypt Arguments */
    unsigned char result[MD5_DIGEST_LENGTH+2];
  char* optStr = "edc:p:h"; 
  int passphrase_specified = 0;	

  /* Use getopt and Fill the structre for arguments */
  int opt = 0;
  while( -1 != (opt = getopt(argc, argv, optStr)) ) 
	{

		switch(opt){
			/* ARG to specify that this is an encryption task 
			 * Make sure that -e and -p options combined are used only once
			 */
		 	case 'e': 
			if(ENCRYPT_OPT_UNKNOWN == xcryptArgs.doEncrypt)
				{
				xcryptArgs.doEncrypt = ENCRYPT_OPT_DO_ENCRYPT;
				}
			else XCRYPT_ERROR("-e and -d options should be used only once"); 
			break;
		
			/* ARG to specify that this is an decryption task 
			 * Make sure that -e and -p options combined are used only once
			 */
		 	case 'd':
			if(ENCRYPT_OPT_UNKNOWN == xcryptArgs.doEncrypt)
				{
				xcryptArgs.doEncrypt = ENCRYPT_OPT_DO_DECRYPT;
				}
			else XCRYPT_ERROR("-e and -d options should be used only once"); 
			break;
	
			
			/* ARG to specify the type of cipher as stringName */
			case 'c':
			printf("Warning : Custom cipherType is not supported in this version of xcrypt\n");
			strcpy(xcryptArgs.xcryptType,optarg); /* This is still sent to kernel space , but used there */
			break;
		
			/* ARG to specify encryption/decryption Key 
			 * Xcipher allows strings of length  atleast 6
 			 */
			case 'p': 
			strcpy(xcryptArgs.encKey , optarg);		
			char* enc_key = optarg;
        		int len = strlen(enc_key);
			if( len < MIN_KEY_LENGTH )
				{
				XCRYPT_ERROR("Please provide an encryption key of length at-least 6");
				}
			else 	
				{
        		memset(result, 0, 16);
			MD5((unsigned char*) enc_key, len, result); /* MD5 to salt the pass-phrase */	
			memcpy(xcryptArgs.encKey, result, 16);		
			passphrase_specified = 1;
				}	
			break;
			
			case 'h':
			print_usage();
			return 0;
			
			default:
			printf("Warning : Unknow argument %c\n",opt);
                   }	
	
	}

 /* Check for potential errors in user-space */
  if( (argc - 2) != optind)
	XCRYPT_ERROR("Please provide input and output Files <Usage>: xcrypt infile outfile"); /* Input-Output Files mandatory*/
 
 if(ENCRYPT_OPT_UNKNOWN == xcryptArgs.doEncrypt) /* Atleast one of -e or -d should be specified */
	XCRYPT_ERROR(" Please Provide encrypt/decrypt option (HINT: Use -e or -d ) ");	

 if( 0 == passphrase_specified)
	XCRYPT_ERROR("Please provide a passphrase to encrypt/decrypt the file [HINT:Use -p ]"); /* Passphrase is madatory */ 
	 
 strcpy(xcryptArgs.infile, argv[optind]);		
 strcpy(xcryptArgs.outfile, argv[optind + 1]);		

	/* Encrypt/Decrypt the File. Get the status and print the message */	
  int xcryptStatus = syscall(XCRYPT_SYSCALL , &xcryptArgs);
	
   if(0 == xcryptStatus) {
			if(ENCRYPT_OPT_DO_ENCRYPT == xcryptArgs.doEncrypt) 
				printf("Successfully encrypted %s into %s!!!\n", xcryptArgs.infile,xcryptArgs.outfile );
			else 
				printf("Successfully decrypted %s into %s!!!\n", xcryptArgs.infile,xcryptArgs.outfile );	
			}
	else { 
	perror("ERROR");
	}
  return 0;
}

