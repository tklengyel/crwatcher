/*
 * Author: (C) Tamas K Lengyel (tamas.lengyel@tum.de)
 * gcc -o crwatcher `pkg-config --cflags --libs glib-2.0 libvmi` crwatcher.c
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <signal.h>
#include <glib.h>

#include <libvmi/libvmi.h>
#include <libvmi/libvmi_extra.h>
#include <libvmi/x86.h>

static const char* page_strings[] = {
    [VMI_PM_UNKNOWN] = "Unknown paging mode",
    [VMI_PM_LEGACY] = "Legacy 32-bit paging",
    [VMI_PM_PAE] = "PAE",
    [VMI_PM_IA32E] = "IA32E"
};

vmi_event_t cr3_event, cr0_event, cr4_event;
reg_t prev_cr0, prev_cr4;
page_mode_t pm;

void print_cr0(reg_t reg, reg_t diff, uint32_t vcpu) {
    printf("CR0=%"PRIx64" on vCPU %u\n", reg, vcpu);
    if((VMI_GET_BIT(diff, 0))) printf("\t%i Protected Mode Enabled (PE)\n", (VMI_GET_BIT(reg, 0)));
    if((VMI_GET_BIT(diff, 1))) printf("\t%i Monitor co-processor (MP)\n", (VMI_GET_BIT(reg, 1)));
    if((VMI_GET_BIT(diff, 2))) printf("\t%i Emulation (EM)\n", (VMI_GET_BIT(reg, 2)));
    if((VMI_GET_BIT(diff, 3))) printf("\t%i Task switched (TS)\n", (VMI_GET_BIT(reg, 3)));
    if((VMI_GET_BIT(diff, 4))) printf("\t%i Extension type (ET)\n", (VMI_GET_BIT(reg, 4)));
    if((VMI_GET_BIT(diff, 5))) printf("\t%i Numeric error (NE)\n", (VMI_GET_BIT(reg, 5)));
    if((VMI_GET_BIT(diff, 16))) printf("\t%i Write protect (WP)\n", (VMI_GET_BIT(reg, 16)));
    if((VMI_GET_BIT(diff, 18))) printf("\t%i Alignment mask (AM)\n", (VMI_GET_BIT(reg, 18)));
    if((VMI_GET_BIT(diff, 29))) printf("\t%i Not-write through (NW)\n", (VMI_GET_BIT(reg, 29)));
    if((VMI_GET_BIT(diff, 30))) printf("\t%i Cache disable (CD)\n", (VMI_GET_BIT(reg, 30)));
    if((VMI_GET_BIT(diff, 31))) printf("\t%i Paging (PG)\n", (VMI_GET_BIT(reg, 31)));
}

void cr0_cb(vmi_instance_t vmi, vmi_event_t *event){
    reg_t check = event->reg_event.value ^ prev_cr0;
    print_cr0(event->reg_event.value, check, event->vcpu_id);
    prev_cr0 = event->reg_event.value;

    pm = vmi_init_paging(vmi, 1);
    printf("\t\tCurrent architecture: %s\n", page_strings[pm]);
}

void cr3_cb(vmi_instance_t vmi, vmi_event_t *event){

    if(event->reg_event.value == event->reg_event.previous)
        return;

    GSList *va_pages = vmi_get_va_pages(vmi, event->reg_event.value);
    GSList *loop = va_pages;

    uint32_t pages = 0;
    uint32_t global_pages = 0;
    uint32_t supervisor_pages = 0;

    while(loop) {
        pages++;
        page_info_t *page = (page_info_t *)loop->data;
        if(page->l1_v && VMI_GET_BIT(page->l1_v,8)) {
            global_pages++;
        }
        if((page->l1_v && !USER_SUPERVISOR(page->l1_v)) || (page->l2_v && !USER_SUPERVISOR(page->l2_v)) || (page->l3_v && !USER_SUPERVISOR(page->l3_v)) || (page->l4_v && !USER_SUPERVISOR(page->l4_v))) {
            supervisor_pages++;
        }
        free(page);
        loop = loop->next;
    }

    printf("CR3=%"PRIx64" on vCPU: %"PRIu32". Number of pages: %u. Global pages: %u. Supervisor pages: %u.\n", event->reg_event.value, event->vcpu_id, pages, global_pages, supervisor_pages);

    g_slist_free(va_pages);
}

void print_cr4(vmi_instance_t vmi,reg_t reg, reg_t diff, uint32_t vcpu) {
    printf("CR4=%"PRIx64" on vCPU %u:\n", reg, vcpu);
    if((VMI_GET_BIT(diff, 0))) printf("\t%i Virtual 8086 Mode Extensions (VME)\n", (VMI_GET_BIT(reg, 0)));
    if((VMI_GET_BIT(diff, 1))) printf("\t%i Protected-mode Virtual Interrupts\t (PVI)\n", (VMI_GET_BIT(reg, 1)));
    if((VMI_GET_BIT(diff, 2))) printf("\t%i Time Stamp Disable (TSD)\n", (VMI_GET_BIT(reg, 2)));
    if((VMI_GET_BIT(diff, 3))) printf("\t%i Debugging Extensions (DE)\n", (VMI_GET_BIT(reg, 3)));
    if((VMI_GET_BIT(diff, 4))) printf("\t%i Page Size Extension (PSE)\n", (VMI_GET_BIT(reg, 4)));
    if((VMI_GET_BIT(diff, 5))) printf("\t%i Physical Address Extension (PAE)\n", (VMI_GET_BIT(reg, 5)));
    if((VMI_GET_BIT(diff, 6))) printf("\t%i Machine Check Exception (MCE)\n", (VMI_GET_BIT(reg, 6)));
    if((VMI_GET_BIT(diff, 7))) {
        printf("\t%i Page Global Enabled (PGE)\n", (VMI_GET_BIT(reg, 7)));
        reg_t rip, cr3;
        vmi_get_vcpureg(vmi, &rip, RIP, vcpu);
        vmi_get_vcpureg(vmi, &cr3, CR3, vcpu);
        printf("\t\tCR3 0x%lx RIP: 0x%lx\n", cr3, rip);
    }
    if((VMI_GET_BIT(diff, 8))) printf("\t%i Performance-Monitoring Counter enable (PCE)\n", (VMI_GET_BIT(reg, 8)));
    if((VMI_GET_BIT(diff, 9))) printf("\t%i Operating system support for FXSAVE and FXRSTOR instructions (OSFXSR)\n", (VMI_GET_BIT(reg, 9)));
    if((VMI_GET_BIT(diff, 10))) printf("\t%i Operating System Support for Unmasked SIMD Floating-Point Exceptions (OSXMMEXCPT)\n", (VMI_GET_BIT(reg, 10)));
    if((VMI_GET_BIT(diff, 13))) printf("\t%i Virtual Machine Extensions Enable (VMXE)\n", (VMI_GET_BIT(reg, 13)));
    if((VMI_GET_BIT(diff, 14))) printf("\t%i Safer Mode Extensions Enable (SMXE)\n", (VMI_GET_BIT(reg, 14)));
    if((VMI_GET_BIT(diff, 17))) printf("\t%i PCID Enable (PCIDE)\n", (VMI_GET_BIT(reg, 17)));
    if((VMI_GET_BIT(diff, 18))) printf("\t%i XSAVE and Processor Extended States Enable (OSXSAVE)\n", (VMI_GET_BIT(reg, 18)));
    if((VMI_GET_BIT(diff, 20))) printf("\t%i Supervisor Mode Execution Protection Enable (SMEP)\n", (VMI_GET_BIT(reg, 20)));
    if((VMI_GET_BIT(diff, 21))) printf("\t%i Supervisor Mode Access Protection Enable (SMAP)\n", (VMI_GET_BIT(reg, 21)));
}

void cr4_cb(vmi_instance_t vmi, vmi_event_t *event){

    reg_t check = event->reg_event.value ^ prev_cr4;
    print_cr4(vmi, event->reg_event.value, check, event->vcpu_id);
    prev_cr4 = event->reg_event.value;
}

static int interrupted = 0;
static void close_handler(int sig){
    interrupted = sig;
}

int main (int argc, char **argv)
{
    vmi_instance_t vmi = NULL;
    status_t status = VMI_SUCCESS;

    struct sigaction act;

    reg_t lstar = 0;
    addr_t phys_lstar = 0;
    reg_t cstar = 0;
    addr_t phys_cstar = 0;
    reg_t sysenter_ip = 0;
    addr_t phys_sysenter_ip = 0;

    addr_t ia32_sysenter_target = 0;
    addr_t phys_ia32_sysenter_target = 0;
    addr_t vsyscall = 0;
    addr_t phys_vsyscall = 0;

    char *name = NULL;
    vmi_pid_t pid = -1;

    if(argc < 2){
        fprintf(stderr, "Usage: events_example <name of VM>\n");
        exit(1);
    }

    pm = VMI_PM_UNKNOWN;

    // Arg 1 is the VM name.
    name = argv[1];

    /* for a clean exit */
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    // Initialize the libvmi library.
    if (vmi_init(&vmi, VMI_XEN | VMI_INIT_PARTIAL | VMI_INIT_EVENTS, name) == VMI_FAILURE){
        printf("Failed to init LibVMI library.\n");
        if (vmi != NULL ) {
            vmi_destroy(vmi);
        }
        return 1;
    }
    else{
        printf("LibVMI init succeeded!\n");
    }


    reg_t cr4;
    vmi_get_vcpureg(vmi, &cr4, CR4, 0);
    printf("Check CR4.PGE: %u\n", VMI_GET_BIT(cr4, 7));

    memset(&cr0_event, 0, sizeof(vmi_event_t));
    memset(&cr3_event, 0, sizeof(vmi_event_t));
    memset(&cr4_event, 0, sizeof(vmi_event_t));

    cr0_event.type = VMI_EVENT_REGISTER;
    cr0_event.reg_event.reg = CR0;
    cr0_event.reg_event.in_access = VMI_REGACCESS_W;
    cr0_event.callback = cr0_cb;
    vmi_register_event(vmi, &cr0_event);

    cr3_event.type = VMI_EVENT_REGISTER;
    cr3_event.reg_event.reg = CR3;
    cr3_event.reg_event.in_access = VMI_REGACCESS_W;
    cr3_event.callback = cr3_cb;
//    vmi_register_event(vmi, &cr3_event);

    cr4_event.type = VMI_EVENT_REGISTER;
    cr4_event.reg_event.reg = CR4;
    cr4_event.reg_event.in_access = VMI_REGACCESS_W;
    cr4_event.callback = cr4_cb;
    vmi_register_event(vmi, &cr4_event);

    while(!interrupted){
        status = vmi_events_listen(vmi,500);
        if (status != VMI_SUCCESS) {
            printf("Error waiting for events, quitting...\n");
            interrupted = -1;
        }
    }
    printf("Finished with test.\n");

leave:
    // cleanup any memory associated with the libvmi instance
    vmi_destroy(vmi);

    return 0;
}
