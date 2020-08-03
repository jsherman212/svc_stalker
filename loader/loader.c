#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <libusb-1.0/libusb.h>

static int get_pongo_device(libusb_device **devices,
        libusb_device_handle **pongo_devicep){
    libusb_device *device = NULL;
    int idx = 0;

    /* this device array is NULL terminated */
    while((device = devices[idx++]) != NULL){
        struct libusb_device_descriptor desc = {0};
        int err = libusb_get_device_descriptor(device, &desc);

        if(err < 0)
            return err;

        if(desc.idVendor == 0x5ac && desc.idProduct == 0x4141)
            return libusb_open(device, pongo_devicep);
    }

    return LIBUSB_ERROR_NO_DEVICE;
}

static int pongo_send_command(libusb_device_handle *pongo_device,
        const char *command){
    size_t command_len = 1;

    if(command)
        command_len += strlen(command);

    return libusb_control_transfer(pongo_device, 0x21, 3, 0, 0,
            (unsigned char *)command, command_len, 0);
}

/*
 * int libusb_control_transfer 	( 	libusb_device_handle *  	dev_handle,
		uint8_t  	bmRequestType,
		uint8_t  	bRequest,
		uint16_t  	wValue,
		uint16_t  	wIndex,
		unsigned char *  	data,
		uint16_t  	wLength,
		unsigned int  	timeout
	)
    */

static int pongo_init_bulk_upload(libusb_device_handle *pongo_device){
    return libusb_control_transfer(pongo_device, 0x21, 1, 0, 0, NULL, 0, 0);
}

static int pongo_discard_bulk_upload(libusb_device_handle *pongo_device){
    return libusb_control_transfer(pongo_device, 0x21, 2, 0, 0, NULL, 0, 0);
}

static int pongo_do_bulk_upload(libusb_device_handle *pongo_device,
        void *data, size_t len){
    return libusb_bulk_transfer(pongo_device, 2, data, len, NULL, 0);
}

int main(int argc, char **argv, const char **envp){
    if(argc < 2){
        printf("usage: loader <pongo module>\n");
        return 1;
    }

    int err = libusb_init(NULL);

    if(err < 0){
        printf("libusb_init failed: %d\n", err);
        return 1;
    }

    libusb_device **devices = NULL;
    int device_count = libusb_get_device_list(NULL, &devices);

    if(device_count < 0){
        printf("libusb_get_device_list failed: %d\n", device_count);
        return 1;
    }

    libusb_device_handle *pongo_device = NULL;
    err = get_pongo_device(devices, &pongo_device);
    
    if(err){
        printf("Couldn't find pongoOS device: %s\n", libusb_error_name(err));
        libusb_free_device_list(devices, 0);
        libusb_exit(NULL);
        return 1;
    }

    libusb_free_device_list(devices, 0);

    printf("Got pongoOS device: %p\n", pongo_device);

    err = libusb_claim_interface(pongo_device, 0);

    if(err < 0){
        printf("libusb_claim_interface: %s\n", libusb_error_name(err));
        libusb_exit(NULL);
        return 1;
    }

    char *module_path = argv[1];
    struct stat st = {0};
    
    if(stat(module_path, &st)){
        printf("Problem stat'ing '%s': %s\n", module_path, strerror(errno));
        libusb_exit(NULL);
        return 1;
    }

    int module_fd = open(module_path, O_RDONLY);

    if(module_fd < 0){
        printf("Problem open'ing '%s': %s\n", module_path, strerror(errno));
        libusb_exit(NULL);
        return 1;
    }

    size_t module_size = st.st_size;
    printf("module size %#lx\n", module_size);
    void *module_data = mmap(NULL, module_size, PROT_READ, MAP_PRIVATE,
            module_fd, 0);

    if(module_data == MAP_FAILED){
        printf("Problem mmap'ing '%s': %s\n", module_path, strerror(errno));
        libusb_exit(NULL);
        return 1;
    }

    err = pongo_init_bulk_upload(pongo_device);

    if(err < 0){
        printf("pongo_init_bulk_upload: %s\n", libusb_error_name(err));
        munmap(module_data, module_size);
        libusb_exit(NULL);
        return 1;
    }

    err = pongo_do_bulk_upload(pongo_device, module_data, module_size);

    if(err < 0){
        printf("pongo_do_bulk_upload: %s\n", libusb_error_name(err));
        munmap(module_data, module_size);
        libusb_exit(NULL);
        return 1;
    }

    err = pongo_send_command(pongo_device, "modload\n");

    if(err < 0){
        printf("pongo_send_command: %s\n", libusb_error_name(err));
        munmap(module_data, module_size);
        libusb_exit(NULL);
        return 1;
    }
    
    munmap(module_data, module_size);

    sleep(1);

    err = pongo_send_command(pongo_device, "stalker-patch\n");

    if(err < 0){
        printf("pongo_send_command: %s\n", libusb_error_name(err));
        libusb_exit(NULL);
        return 1;
    }

    printf("Hit enter to boot XNU\n");
    getchar();

    sleep(1);
    
    err = pongo_send_command(pongo_device, "bootx\n");

    if(err < 0){
        printf("pongo_send_command: %s\n", libusb_error_name(err));
        libusb_exit(NULL);
        return 1;
    }

    libusb_exit(NULL);

    return 0;
}
