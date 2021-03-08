# d3dev && d3dev-revenge

## Before

一个signin pwn，考点是比较基础的利用virtual device进行qemu逃逸，有做过类似题型的应该可以很快解决;

然而由于部署的时候出现了非预期（非常抱歉－_－|||），不得不降分然后开了个新题.

## Analysis

漏洞位置很明显。在`d3dev_mmio_write`中可以看到通过mmio向`opaque->blocks`中写入数据时使用的是：

```c
void __fastcall d3dev_mmio_write(d3devState *opaque, hwaddr addr, uint64_t val, unsigned int size)
...
	pos = opaque->seek + (unsigned int)(addr >> 3);
    if ( opaque->mmio_write_part )
    {
        ...
    }
    else
    {
        ...
        opaque->blocks[pos] = (unsigned int)val;
    }
...
```

`addr`和`val`是用户可控的，虽然`addr`不能直接超过mmio的内存范围来达到溢出，但是如果能控制`seek`的大小就可以做到.

查看`d3dev_pmio_write`发现seek是可以通过令`addr==8`直接控制的:

```c
  if ( addr == 8 )
  {
    if ( val <= 0x100 )
      opaque->seek = val;
  }
```

溢出思路可行之后，观察`d3devState`结构体：

```c
00000000 ; Ins/Del : create/delete structure
00000000 ; D/A/*   : create structure member (data/ascii/array)
00000000 ; N       : rename structure or structure member
00000000 ; U       : delete structure member
00000000 ; ---------------------------------------------------------------------------
00000000
00000000 d3devState      struc ; (sizeof=0x1300, align=0x10, copyof_4545)
00000000 pdev            PCIDevice_0 ?
000008E0 mmio            MemoryRegion_0 ?
000009D0 pmio            MemoryRegion_0 ?
00000AC0 memory_mode     dd ?
00000AC4 seek            dd ?
00000AC8 init_flag       dd ?
00000ACC mmio_read_part  dd ?
00000AD0 mmio_write_part dd ?
00000AD4 r_seed          dd ?
00000AD8 blocks          dq 257 dup(?)
000012E0 key             dd 4 dup(?)
000012F0 rand_r          dq ?                    ; offset
000012F8                 db ? ; undefined
000012F9                 db ? ; undefined
000012FA                 db ? ; undefined
000012FB                 db ? ; undefined
000012FC                 db ? ; undefined
000012FD                 db ? ; undefined
000012FE                 db ? ; undefined
000012FF                 db ? ; undefined
00001300 d3devState      ends
00001300
```

可以看到`blocks`往后有一个函数指针，该指针保存`rand_r`函数地址，并在`d3dev_pmio_write`中被调用：

```c
    if ( addr == 28 )
    {
      opaque->r_seed = val;
      v4 = opaque->key;
      do
        *v4++ = ((__int64 (__fastcall *)(uint32_t *, __int64, uint64_t, _QWORD))opaque->rand_r)(
                  &opaque->r_seed,
                  28LL,
                  val,
                  *(_QWORD *)&size);
      while ( v4 != (uint32_t *)&opaque->rand_r );
    }
```

在这个分支中`rand_r`使用`opaque->r_seed`作为参数生成128位的`opaque->key`；

所以只要同时控制好`opaque->r_seed`和`opaque->rand_r`就可以构造出`system("/bin/sh\x00")`；

> By the way, 对于这题，在写入数据和读取数据的时候其实不用分成两次四字节来读写，有兴趣的话可以再仔细看看

利用上的各种细节请查看exp.

## Author

赤道企鹅 eqqie
