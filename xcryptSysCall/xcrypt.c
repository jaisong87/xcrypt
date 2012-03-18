#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <asm/errno.h>

long (*xcryptImpl)(void* args) = NULL; /* Function Pointer to implementation of Xcrypt system Call */
EXPORT_SYMBOL(xcryptImpl); 

asmlinkage long sys_xcrypt(void* args)
{
  
  printk(KERN_ALERT " Xcrypt system call recieved");
	
  if(NULL == xcryptImpl)
	{
  	printk(KERN_ALERT " XcryptImpl ERROR! - No implementation specified for Xcrypt");
	return -ENOSYS;
	}
 
  printk(KERN_ALERT " XcryptImpl Found  : Calling Implementation");

   return xcryptImpl(args);
}
