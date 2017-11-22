CC                   = gcc
AS                   = gcc
AR                   = ar
LD                   = gcc
CFLAGS              += -fPIC -fno-stack-protector -fno-builtin -fno-jump-tables -fno-common -Wno-attributes -O2
ARFLAGS              = -rcs
OBJECTS              = attack_demo.o set_sched.o cache.o
OUTPUT               = attack_demo
SGX_SDK		     = /home/haha/tmp/linux-sgx/linux/installer/bin/sgxsdk
INCLUDE              = -I $(SGX_SDK)/include/
SGX_LIBRARY_PATH     = $(SGX_SDK)/sdk_libs

.SILENT:
all:	$(OUTPUT)
	
ifneq ($(SGX_MODE), HW)
        Urts_Library_Name := sgx_urts_sim
else
        Urts_Library_Name := sgx_urts
endif

LINK 		     = -pthread -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name)


$(OUTPUT): $(OBJECTS)
	$(LD) $(OBJECTS) $(LINK) -o $(OUTPUT) 
	
%.o : %.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $<

clean:
	rm $(OBJECTS)
	rm $(OUTPUT)
