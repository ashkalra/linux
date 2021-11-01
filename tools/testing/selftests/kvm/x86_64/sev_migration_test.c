// SPDX-License-Identifier: GPL-2.0-only
/*
 * Basic SEV migration test
 *
 * Copyright (C) 2021 Advanced Micro Devices
 */
#define _GNU_SOURCE /* for program_invocation_short_name */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include "test_util.h"

#include "kvm_util.h"
#include "processor.h"
#include "svm_util.h"
#include "linux/psp-sev.h"
#include "sev.h"
#include "sev_exitlib.h"

#define VCPU_ID			2
#define PAGE_SIZE		4096
#define PAGE_STRIDE		64

#define SHARED_PAGES		256
#define SHARED_VADDR_MIN	0x1000000

#define PRIVATE_PAGES		256
#define PRIVATE_VADDR_MIN	(SHARED_VADDR_MIN + SHARED_PAGES * PAGE_SIZE)

#define TOTAL_PAGES		(512 + SHARED_PAGES + PRIVATE_PAGES)

static void fill_buf(uint8_t *buf, size_t pages, size_t stride, uint8_t val)
{
	int i, j;

	for (i = 0; i < pages; i++)
		for (j = 0; j < PAGE_SIZE; j += stride)
			buf[i * PAGE_SIZE + j] = val;
}

static bool check_buf(uint8_t *buf, size_t pages, size_t stride, uint8_t val)
{
	int i, j;

	for (i = 0; i < pages; i++)
		for (j = 0; j < PAGE_SIZE; j += stride)
			if (buf[i * PAGE_SIZE + j] != val)
				return false;
	return true;
}

static void guest_test_start(struct sev_sync_data *sync)
{
	/* Initial guest check-in. */
	sev_guest_sync(sync, 1, 0);
}

static void check_test_start(struct kvm_vm *vm, struct sev_sync_data *sync)
{
	struct kvm_run *run;

	run = vcpu_state(vm, VCPU_ID);
	vcpu_run(vm, VCPU_ID);

	/* Initial guest check-in. */
	sev_check_guest_sync(run, sync, 1);

}

static void
guest_test_common(struct sev_sync_data *sync, uint8_t *shared_buf, uint8_t *private_buf)
{
	bool success;

	/* Initial check-in for common. */
	sev_guest_sync(sync, 100, 0);

	/* Ensure initial shared pages are intact. First page is used for sync. */
	success = check_buf(shared_buf, SHARED_PAGES, PAGE_STRIDE, 0x41);
	SEV_GUEST_ASSERT(sync, 103, success);

	/* Ensure initial private pages are intact/encrypted. */
	success = check_buf(private_buf, PRIVATE_PAGES, PAGE_STRIDE, 0x42);
	SEV_GUEST_ASSERT(sync, 104, success);

	/* Ensure host userspace can't read newly-written encrypted data. */
	fill_buf(private_buf, PRIVATE_PAGES, PAGE_STRIDE, 0x43);

	sev_guest_sync(sync, 200, 0);

	/* Ensure guest can read newly-written shared data from host. */
	success = check_buf(shared_buf, SHARED_PAGES, PAGE_STRIDE, 0x44);
	SEV_GUEST_ASSERT(sync, 201, success);

	/* Ensure host can read newly-written shared data from guest. */
	fill_buf(shared_buf, SHARED_PAGES, PAGE_STRIDE, 0x45);

	sev_guest_sync(sync, 300, 0);
}

static void
check_test_common(struct kvm_vm *vm, struct sev_sync_data *sync,
		  uint8_t *shared_buf, uint8_t *private_buf)
{
	struct kvm_run *run = vcpu_state(vm, VCPU_ID);
	bool success;

	/* Initial guest check-in. */
	vcpu_run(vm, VCPU_ID);
	sev_check_guest_sync(run, sync, 100);

	/* Ensure the initial memory contents were encrypted. */
	success = check_buf(private_buf, PRIVATE_PAGES, PAGE_STRIDE, 0x42);
	TEST_ASSERT(!success, "Initial guest memory not encrypted!");

	vcpu_run(vm, VCPU_ID);
	sev_check_guest_sync(run, sync, 200);

	/* Ensure host userspace can't read newly-written encrypted data. */
	success = check_buf(private_buf, PRIVATE_PAGES, PAGE_STRIDE, 0x43);
	TEST_ASSERT(!success, "Modified guest memory not encrypted!");

	/* Ensure guest can read newly-written shared data from host. */
	fill_buf(shared_buf, SHARED_PAGES, PAGE_STRIDE, 0x44);

	vcpu_run(vm, VCPU_ID);
	sev_check_guest_sync(run, sync, 300);

	/* Ensure host can read newly-written shared data from guest. */
	success = check_buf(shared_buf, SHARED_PAGES, PAGE_STRIDE, 0x45);
	TEST_ASSERT(success, "Host can't read shared guest memory!");
}

static void
guest_test_done(struct sev_sync_data *sync)
{
	sev_guest_done(sync, 10000, 0);
}

static void
check_test_done(struct kvm_vm *vm, struct sev_sync_data *sync)
{
	struct kvm_run *run = vcpu_state(vm, VCPU_ID);

	vcpu_run(vm, VCPU_ID);
	sev_check_guest_done(run, sync, 10000);
}

static void __attribute__((__flatten__))
guest_sev_code(struct sev_sync_data *sync, uint8_t *shared_buf, uint8_t *private_buf)
{
	uint32_t eax, ebx, ecx, edx;
	uint64_t sev_status;

	guest_test_start(sync);

	/* Check common SEV CPUID bits. */
	eax = 0x8000001f;
	ecx = 0;
	cpuid(&eax, &ebx, &ecx, &edx);
	SEV_GUEST_ASSERT(sync, 2, eax & (1 << 1));

	/* Check common SEV MSR bits. */
	sev_status = rdmsr(MSR_AMD64_SEV);
	SEV_GUEST_ASSERT(sync, 3, (sev_status & 0x1) == 1);

	guest_test_common(sync, shared_buf, private_buf);

	guest_test_done(sync);
}

static void
setup_test_common_source(struct sev_vm *sev, void *guest_code, vm_vaddr_t *sync_vaddr,
			 vm_vaddr_t *shared_vaddr, vm_vaddr_t *private_vaddr)
{
	struct kvm_vm *vm = sev_get_vm(sev);
	uint8_t *shared_buf, *private_buf;

	/* Set up VCPU and initial guest kernel. */
	vm_vcpu_add_default(vm, VCPU_ID, guest_code);
	kvm_vm_elf_load(vm, program_invocation_name);

	/* Set up shared sync buffer. */
	*sync_vaddr = vm_vaddr_alloc_shared(vm, PAGE_SIZE, 0);

	/* Set up buffer for reserved shared memory. */
	*shared_vaddr = vm_vaddr_alloc_shared(vm, SHARED_PAGES * PAGE_SIZE,
					      SHARED_VADDR_MIN);
	shared_buf = addr_gva2hva(vm, *shared_vaddr);
	fill_buf(shared_buf, SHARED_PAGES, PAGE_STRIDE, 0x41);

	/* Set up buffer for reserved private memory. */
	*private_vaddr = vm_vaddr_alloc(vm, PRIVATE_PAGES * PAGE_SIZE,
					PRIVATE_VADDR_MIN);
	private_buf = addr_gva2hva(vm, *private_vaddr);
	fill_buf(private_buf, PRIVATE_PAGES, PAGE_STRIDE, 0x42);
}

static void
setup_test_common_remote(struct sev_vm *sev)
{
	struct kvm_vm *vm = sev_get_vm(sev);

	/* Create VCPU */
	vm_vcpu_add(vm, VCPU_ID);
	vcpu_set_cpuid(vm, VCPU_ID, kvm_get_supported_cpuid());
}

static void start_sev_guests_and_migrate(void *guest_code, uint64_t policy)
{
	vm_vaddr_t sync_vaddr, shared_vaddr, private_vaddr;
	size_t remote_pdh_len, remote_plat_cert_len;
	unsigned char *remote_pdh, *remote_plat_cert;
	struct sev_sync_data *rem_sync, *sync;
	uint8_t *shared_buf, *private_buf;
	struct kvm_vm *vm, *remote_vm;
	unsigned char *session, *pdh;
	size_t pdh_len, session_len;
	struct sev_vm *remote_sev;
	uint8_t measurement[512];
	struct sev_vm *sev;
	struct kvm_run *run;
	u32 remote_policy;
	int i;

	/* start incoming sev guest */
	remote_sev = sev_vm_create(policy, TOTAL_PAGES);
	if (!remote_sev)
		return;
	remote_vm = sev_get_vm(remote_sev);

	setup_test_common_remote(remote_sev);

	sev_get_pdh_info(remote_sev, &remote_pdh, &remote_pdh_len,
			 &remote_plat_cert, &remote_plat_cert_len);

	pr_info("outgoing sev guest created, waiting to resume ...\n");

	/* start outgoing sev guest */
	sev = sev_vm_create(policy, TOTAL_PAGES);
	if (!sev)
		return;
	vm = sev_get_vm(sev);

	setup_test_common_source(sev, guest_code, &sync_vaddr, &shared_vaddr,
				 &private_vaddr);

	vcpu_args_set(vm, VCPU_ID, 4, sync_vaddr, shared_vaddr, private_vaddr);

	sync = addr_gva2hva(vm, sync_vaddr);
	shared_buf = addr_gva2hva(vm, shared_vaddr);
	private_buf = addr_gva2hva(vm, private_vaddr);

	/*
	 * Need to get remote host virtual mapping to the shared
	 * "sync" buffer, addr_gva2hva() needs to get gpa, but
	 * remote VM does not have any guest page tables setup yet,
	 * and once guest page tables are migrated, we can't access
	 * them as they will be encrypted.
	 * The solution is to get gva2gpa mapping from the source VM
	 * page tables and then do gpa2hva mapping using the remote VM.
	 */
	rem_sync = addr_gpa2hva(remote_vm, addr_gva2gpa(vm, sync_vaddr));

	/* Allocations/setup done. Encrypt initial guest payload. */
	sev_vm_launch(sev);

	/* Dump the initial measurement. A test to actually verify it would be nice. */
	sev_vm_measure(sev, measurement);
	pr_info("guest measurement: ");
	for (i = 0; i < 32; ++i)
		pr_info("%02x", measurement[i]);
	pr_info("\n");

	sev_vm_launch_finish(sev);

	/* Guest is ready to run. Do the tests. */
	check_test_start(vm, sync);
	check_test_common(vm, sync, shared_buf, private_buf);
	check_test_done(vm, sync);

	/* start migration */

	/* setup shared encryption context between source and remote VMs */
	sev_send_start(sev, &remote_policy, &session_len,
		       &session, remote_pdh_len, remote_pdh,
		       remote_plat_cert_len, remote_plat_cert,
		       remote_pdh_len, remote_pdh, &pdh_len,
		       &pdh);

	sev_receive_start(remote_sev, remote_policy, pdh_len,
			  pdh, session_len, session);

	sev_migrate_data(sev, remote_sev);

	/* migrate VMSA(s) */
	sev_migrate_vmsas(sev, remote_sev);

	/* migration completion */
	sev_send_finish(sev);
	sev_receive_finish(remote_sev);

	/* check if remote VM has been resumed correctly */
	run = vcpu_state(remote_vm, VCPU_ID);
	vcpu_run(remote_vm, VCPU_ID);
	sev_check_guest_done(run, rem_sync, 10000);

	pr_info("Migration completed\n");
	sev_vm_free(sev);
	sev_vm_free(remote_sev);
}

int main(int argc, char *argv[])
{
	start_sev_guests_and_migrate(guest_sev_code, 0);

	return 0;
}
