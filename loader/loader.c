#include <CoreFoundation/CoreFoundation.h>
#include <errno.h>
#include <IOKit/IOCFPlugin.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/usb/IOUSBLib.h>
#include <stdio.h>
#include <stdlib.h>
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
            return 1;

        if(desc.idVendor == 0x5ac && desc.idProduct == 0x4141)
            return libusb_open(device, pongo_devicep);
    }

    return 0;
}

static int send_pongo_command(libusb_device_handle *pongo_device,
        const char *command){
    if(!command)
        return -999;

    size_t command_len = strlen(command) + 1;

    return libusb_control_transfer(pongo_device, 0x21, 3, 0, 0,
            (unsigned char *)command, command_len, 0);
}

int main(int argc, char **argv, const char **envp){
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
        printf("Couldn't find pongoOS device\n");
        libusb_exit(NULL);
        return 1;
    }

    libusb_free_device_list(devices, 0);

    printf("Got pongoOS device: %p\n", pongo_device);

    /* as a test, boot XNU */
    err = send_pongo_command(pongo_device, "bootx\n");

    if(err < 0){
        printf("Failed sending bootx pongo command: %s\n", libusb_error_name(err));
        return 1;
    }

    printf("Device should boot XNU now\n");

    return 0;
}
