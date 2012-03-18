#ifndef __XCRYPT_UTILS_H__
#define __XCRYPT_UTILS_H__

#define XCRYPT_SYSCALL 349
#define ENCRYPT_OPT_UNKNOWN 2
#define ENCRYPT_OPT_DO_ENCRYPT 1
#define ENCRYPT_OPT_DO_DECRYPT 0
#define MIN_KEY_LENGTH 6
#define HASH_KEY_LENGTH 16
#define MAX_FILE_LENGTH 1024

#define XCRYPT_ERROR(errMsg) { fprintf(stderr, "ERROR : %s\n", errMsg /*,__FILE__,__LINE__*/ );  return -1; } 

struct xcryptParams {
 int doEncrypt; /* doEncrypt or doDecrypt LSB=1 means doEncrypt else doDecrypt */
 char xcryptType[10]; /* Type of Cipher */
 char encKey[HASH_KEY_LENGTH+2]; /* Encryption Key */
 int keylen; /* Length of the encryption key */
 char infile[MAX_FILE_LENGTH]; /* Input File */
 char outfile[MAX_FILE_LENGTH]; /* Output File */
};
#endif 
