#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <errno.h>
#include <error.h>


/*
 *   gcc xxx.c -o xxx  -ldl
 *
 */

#define LOAD_FLAG   RTLD_LAZY



int main(int argc, char **argv) {
    
    void *handle;
    void *funcptr;
    
    if(argc != 3) {
        fprintf(stderr,"usage: %s libpath  funcname\n",argv[0]);
        fprintf(stderr,"e.g. : %s /usr/lib/libc.so  system\n",argv[0]);
        exit(-1);
    }
    
    if( 0 >= (handle = dlopen(argv[1],LOAD_FLAG))){
        fprintf(stderr,"error detail:%s\n",dlerror());
        exit(-1);
    }

    dlerror();    /* Clear any existing error */

    //printf("handle = 0x%08x\n",handle);
    //printf("base_addr = 0x%08x\n",*(long*)handle);

    if(0 >= (funcptr = dlsym(handle,argv[2]))) {
        perror("ldsym");
        fprintf(stderr,"error detail:%s\n",dlerror());
        exit(-1);
    }              
    //printf("func_addr   = 0x%08x\n",funcptr);
    //printf("func_offset = 0x%08x\n",(long)funcptr - *(long*)handle);
    printf("0x%08x",(long)funcptr - *(long*)handle);
    dlclose(handle);
    //getchar();
    return 0;
}
