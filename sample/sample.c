#include <mach/mach.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

kern_return_t catch_mach_exception_raise_state(mach_port_t exception_port, exception_type_t exception, exception_data_t code, mach_msg_type_number_t code_count, int *flavor, thread_state_t in_state, mach_msg_type_number_t in_state_count, thread_state_t out_state, mach_msg_type_number_t *out_state_count){return KERN_FAILURE;}

kern_return_t catch_mach_exception_raise_state_identity(mach_port_t exception_port, mach_port_t thread, mach_port_t task, exception_type_t exception, exception_data_t code, mach_msg_type_number_t code_count, int *flavor, thread_state_t in_state, mach_msg_type_number_t in_state_count, thread_state_t out_state, mach_msg_type_number_t *out_state_count){return KERN_FAILURE;}

kern_return_t catch_mach_exception_raise(mach_port_t exception_port,
        mach_port_t thread, mach_port_t task, exception_type_t exception,
        exception_data_t code, mach_msg_type_number_t code_count){
    printf("%s: exception_port %#x thread %#x task %#x exception %#x"
            " code[0] %#lx code[1] %#lx code_count %d\n", __func__,
            exception_port, thread, task, exception, ((long *)code)[0],
            ((long *)code)[1], code_count);

    sleep(999999999);

    return KERN_SUCCESS;
}

static void *exc_thread_func(void *arg){
    printf("%s: starting\n", __func__);
    mach_port_t exc_port = (mach_port_t)arg;

    for(;;){
        extern boolean_t mach_exc_server(mach_msg_header_t *InHeadP,
                mach_msg_header_t *OutHeadP);
        mach_msg_server_once(mach_exc_server, 4096, exc_port, 0);
    }

    return NULL;
}

int main(void){
    /* int err = syscall(0); */
    /* printf("err %d\n"); */
    /* return 0; */
    mach_port_t exc_port;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exc_port);
    mach_port_insert_right(mach_task_self(), exc_port, exc_port, MACH_MSG_TYPE_MAKE_SEND);

    kern_return_t kret = task_set_exception_ports(mach_task_self(), EXC_MASK_ALL, exc_port,
            EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, THREAD_STATE_NONE);
    printf("task_set_exception_ports %s\n", mach_error_string(kret));

    pthread_t exc_thread;
    pthread_create(&exc_thread, NULL, exc_thread_func, (void *)exc_port);
    sleep(1);

    uint64_t var0 = 0;
    uint64_t var1 = 0;

    printf("%#llx\n", syscall(531, &var0, &var1));
    printf("%#llx %#llx\n", var0, var1);

    /* syscall(-10, 0); */


    asm volatile("mov x16, -10");
    asm volatile("svc 0x80");

    /* asm volatile("brk 0"); */

    //sleep(1);
    write(1, "Calling write in C\n", strlen("Calling write in C\n"));

    const char *str = "Calling write in assembly\n";
    size_t len = strlen(str);

    asm volatile("mov w0, 1");
    asm volatile("mov x1, %0" : : "r" (str) : );
    asm volatile("mov x2, %0" : : "r" (len) : );
    asm volatile("mov x16, 4");
    asm volatile("svc 0");

    write(1, "Calling write in C again\n", strlen("Calling write in C again\n"));

    char buf[0x100];
    size_t bufsz = sizeof(buf);

    //    read(0, buf, bufsz);

    asm volatile("mov w0, 0");
    asm volatile("mov x1, %0" : : "r" (buf) : );
    asm volatile("mov x2, %0" : : "r" (bufsz) : );
    asm volatile("mov x16, 3");
    asm volatile("svc 0");

    //    asm volatile("mov x0, 50");
    //  asm volatile("mov x16, 1");
    //asm volatile("svc 0");
    //exit(50);

    return 0;
}
