CC                   = gcc
AS                   = gcc
AR                   = ar
LD                   = gcc
CFLAGS              += -fPIC -fno-stack-protector -fno-builtin -fno-jump-tables -fno-common -Wno-attributes -O2
ARFLAGS              = -rcs
OBJECTS              = attack_demo.o set_sched.o cache.o
OUTPUT               = attack_demo
LINK 		     = -pthread

.SILENT:
all:	$(OUTPUT)
	
$(OUTPUT): $(OBJECTS)
	$(LD) $(OBJECTS) $(LINK) -o $(OUTPUT) 
	
%.o : %.c
	$(CC) $(CFLAGS) $(LINK) -c $<

clean:
	rm $(OBJECTS)
	rm $(OUTPUT)
