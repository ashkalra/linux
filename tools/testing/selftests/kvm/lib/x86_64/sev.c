// SPDX-License-Identifier: GPL-2.0-only
/*
 * Helpers used for SEV guests
 *
 * Copyright (C) 2021 Advanced Micro Devices
 */

#include <stdint.h>
#include <stdbool.h>
#include "kvm_util.h"
#include "linux/psp-sev.h"
#include "processor.h"
#include "sev.h"

#define PAGE_SHIFT		12
#define PAGE_SIZE		(1UL << PAGE_SHIFT)

struct sev_vm {
	struct kvm_vm *vm;
	int fd;
	int enc_bit;
	uint32_t sev_policy;
	uint64_t snp_policy;
};

/* Helpers for coordinating between guests and test harness. */

void sev_guest_sync(struct sev_sync_data *sync, uint32_t token, uint64_t info)
{
	sync->token = token;
	sync->info = info;
	sync->pending = true;

	asm volatile("hlt" : : : "memory");
}

void sev_guest_done(struct sev_sync_data *sync, uint32_t token, uint64_t info)
{
	while (true) {
		sync->done = true;
		sev_guest_sync(sync, token, info);
	}
}

void sev_guest_abort(struct sev_sync_data *sync, uint32_t token, uint64_t info)
{
	while (true) {
		sync->aborted = true;
		sev_guest_sync(sync, token, info);
	}
}

void sev_check_guest_sync(struct kvm_run *run, struct sev_sync_data *sync,
			  uint32_t token)
{
	TEST_ASSERT(run->exit_reason == KVM_EXIT_HLT,
		    "unexpected exit reason: %u (%s)",
		    run->exit_reason, exit_reason_str(run->exit_reason));
	TEST_ASSERT(sync->token == token,
		    "unexpected guest token, expected %d, got: %d", token,
		    sync->token);
	TEST_ASSERT(!sync->done, "unexpected guest state");
	TEST_ASSERT(!sync->aborted, "unexpected guest state");
	sync->pending = false;
}

void sev_check_guest_done(struct kvm_run *run, struct sev_sync_data *sync,
			  uint32_t token)
{
	TEST_ASSERT(run->exit_reason == KVM_EXIT_HLT,
		    "unexpected exit reason: %u (%s)",
		    run->exit_reason, exit_reason_str(run->exit_reason));
	TEST_ASSERT(sync->token == token,
		    "unexpected guest token, expected %d, got: %d", token,
		    sync->token);
	TEST_ASSERT(sync->done, "unexpected guest state");
	TEST_ASSERT(!sync->aborted, "unexpected guest state");
	sync->pending = false;
}

/* Common SEV helpers/accessors. */

struct kvm_vm *sev_get_vm(struct sev_vm *sev)
{
	return sev->vm;
}

uint8_t sev_get_enc_bit(struct sev_vm *sev)
{
	return sev->enc_bit;
}

void sev_ioctl(int sev_fd, int cmd, void *data)
{
	int ret;
	struct sev_issue_cmd arg;

	arg.cmd = cmd;
	arg.data = (unsigned long)data;
	ret = ioctl(sev_fd, SEV_ISSUE_CMD, &arg);
	TEST_ASSERT(ret == 0,
		    "SEV ioctl %d failed, error: %d, fw_error: %d",
		    cmd, ret, arg.error);
}

void kvm_sev_ioctl(struct sev_vm *sev, int cmd, void *data)
{
	struct kvm_sev_cmd arg = {0};
	int ret;

	arg.id = cmd;
	arg.sev_fd = sev->fd;
	arg.data = (__u64)data;

	ret = ioctl(vm_get_fd(sev->vm), KVM_MEMORY_ENCRYPT_OP, &arg);
	TEST_ASSERT(ret == 0,
		    "SEV KVM ioctl %d failed, rc: %i errno: %i (%s), fw_error: %d",
		    cmd, ret, errno, strerror(errno), arg.error);
}

/* Local helpers. */

static bool sev_snp_enabled(struct sev_vm *sev)
{
	/* RSVD is always 1 for SNP guests. */
	return sev->snp_policy & SNP_POLICY_RSVD;
}

static void
sev_register_user_range(struct sev_vm *sev, void *hva, uint64_t size)
{
	struct kvm_enc_region range = {0};
	int ret;

	pr_debug("register_user_range: hva: %p, size: %lu\n", hva, size);

	range.addr = (__u64)hva;
	range.size = size;

	ret = ioctl(vm_get_fd(sev->vm), KVM_MEMORY_ENCRYPT_REG_REGION, &range);
	TEST_ASSERT(ret == 0, "failed to register user range, errno: %i\n", errno);
}

static void
sev_encrypt_phy_range(struct sev_vm *sev, vm_paddr_t gpa, uint64_t size)
{
	struct kvm_sev_launch_update_data ksev_update_data = {0};

	pr_debug("encrypt_phy_range: addr: 0x%lx, size: %lu\n", gpa, size);

	ksev_update_data.uaddr = (__u64)addr_gpa2hva(sev->vm, gpa);
	ksev_update_data.len = size;

	kvm_sev_ioctl(sev, KVM_SEV_LAUNCH_UPDATE_DATA, &ksev_update_data);
}

static void
sev_snp_encrypt_phy_range(struct sev_vm *sev, vm_paddr_t gpa, uint64_t size)
{
	struct kvm_sev_snp_launch_update update_data = {0};

	pr_debug("encrypt_phy_range: addr: 0x%lx, size: %lu\n", gpa, size);

	update_data.uaddr = (__u64)addr_gpa2hva(sev->vm, gpa);
	update_data.start_gfn = gpa >> PAGE_SHIFT;
	update_data.len = size;
	update_data.page_type = KVM_SEV_SNP_PAGE_TYPE_NORMAL;

	kvm_sev_ioctl(sev, KVM_SEV_SNP_LAUNCH_UPDATE, &update_data);
}

static void sev_encrypt(struct sev_vm *sev)
{
	struct sparsebit *enc_phy_pages;
	struct kvm_vm *vm = sev->vm;
	sparsebit_idx_t pg = 0;
	vm_paddr_t gpa_start;
	uint64_t memory_size;

	/* Only memslot 0 supported for now. */
	enc_phy_pages = vm_get_encrypted_phy_pages(sev->vm, 0, &gpa_start, &memory_size);
	TEST_ASSERT(enc_phy_pages, "Unable to retrieve encrypted pages bitmap");
	while (pg < (memory_size / vm_get_page_size(vm))) {
		sparsebit_idx_t pg_cnt;

		if (sparsebit_is_clear(enc_phy_pages, pg)) {
			pg = sparsebit_next_set(enc_phy_pages, pg);
			if (!pg)
				break;
		}

		pg_cnt = sparsebit_next_clear(enc_phy_pages, pg) - pg;
		if (pg_cnt <= 0)
			pg_cnt = 1;

		if (sev_snp_enabled(sev))
			sev_snp_encrypt_phy_range(sev,
						  gpa_start + pg * vm_get_page_size(vm),
						  pg_cnt * vm_get_page_size(vm));
		else
			sev_encrypt_phy_range(sev,
					      gpa_start + pg * vm_get_page_size(vm),
					      pg_cnt * vm_get_page_size(vm));
		pg += pg_cnt;
	}

	sparsebit_free(&enc_phy_pages);
}

/* SEV VM implementation. */

static struct sev_vm *sev_common_create(struct kvm_vm *vm)
{
	struct sev_user_data_status sev_status = {0};
	uint32_t eax, ebx, ecx, edx;
	struct sev_vm *sev;
	int sev_fd;

	sev_fd = open(SEV_DEV_PATH, O_RDWR);
	if (sev_fd < 0) {
		pr_info("Failed to open SEV device, path: %s, error: %d, skipping test.\n",
			SEV_DEV_PATH, sev_fd);
		return NULL;
	}

	sev_ioctl(sev_fd, SEV_PLATFORM_STATUS, &sev_status);

	if (!(sev_status.api_major > SEV_FW_REQ_VER_MAJOR ||
	      (sev_status.api_major == SEV_FW_REQ_VER_MAJOR &&
	       sev_status.api_minor >= SEV_FW_REQ_VER_MINOR))) {
		pr_info("SEV FW version too old. Have API %d.%d (build: %d), need %d.%d, skipping test.\n",
			sev_status.api_major, sev_status.api_minor, sev_status.build,
			SEV_FW_REQ_VER_MAJOR, SEV_FW_REQ_VER_MINOR);
		return NULL;
	}

	sev = calloc(1, sizeof(*sev));
	sev->fd = sev_fd;
	sev->vm = vm;

	/* Get encryption bit via CPUID. */
	eax = 0x8000001f;
	ecx = 0;
	cpuid(&eax, &ebx, &ecx, &edx);
	sev->enc_bit = ebx & 0x3F;

	return sev;
}

static void sev_common_free(struct sev_vm *sev)
{
	close(sev->fd);
	free(sev);
}

struct sev_vm *sev_vm_create(uint32_t policy, uint64_t npages)
{
	struct sev_vm *sev;
	struct kvm_vm *vm;

	/* Need to handle memslots after init, and after setting memcrypt. */
	vm = vm_create(VM_MODE_DEFAULT, 0, O_RDWR);
	sev = sev_common_create(vm);
	if (!sev)
		return NULL;
	sev->sev_policy = policy;

	if (sev->sev_policy & SEV_POLICY_ES)
		kvm_sev_ioctl(sev, KVM_SEV_ES_INIT, NULL);
	else
		kvm_sev_ioctl(sev, KVM_SEV_INIT, NULL);

	vm_set_memory_encryption(vm, true, true, sev->enc_bit);
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, 0, 0, npages, 0);
	sev_register_user_range(sev, addr_gpa2hva(vm, 0), npages * vm_get_page_size(vm));

	pr_info("%s guest created, policy: 0x%x, size: %lu KB\n",
		(sev->sev_policy & SEV_POLICY_ES) ? "SEV-ES" : "SEV",
		sev->sev_policy, npages * vm_get_page_size(vm) / 1024);

	return sev;
}

void sev_vm_free(struct sev_vm *sev)
{
	kvm_vm_free(sev->vm);
	sev_common_free(sev);
}

void sev_vm_launch(struct sev_vm *sev)
{
	struct kvm_sev_launch_start ksev_launch_start = {0};
	struct kvm_sev_guest_status ksev_status = {0};

	ksev_launch_start.policy = sev->sev_policy;
	kvm_sev_ioctl(sev, KVM_SEV_LAUNCH_START, &ksev_launch_start);
	kvm_sev_ioctl(sev, KVM_SEV_GUEST_STATUS, &ksev_status);
	TEST_ASSERT(ksev_status.policy == sev->sev_policy, "Incorrect guest policy.");
	TEST_ASSERT(ksev_status.state == SEV_GSTATE_LUPDATE,
		    "Unexpected guest state: %d", ksev_status.state);

	sev_encrypt(sev);

	if (sev->sev_policy & SEV_POLICY_ES)
		kvm_sev_ioctl(sev, KVM_SEV_LAUNCH_UPDATE_VMSA, NULL);
}

void sev_vm_measure(struct sev_vm *sev, uint8_t *measurement)
{
	struct kvm_sev_launch_measure ksev_launch_measure = {0};
	struct kvm_sev_guest_status ksev_guest_status = {0};

	ksev_launch_measure.len = 256;
	ksev_launch_measure.uaddr = (__u64)measurement;
	kvm_sev_ioctl(sev, KVM_SEV_LAUNCH_MEASURE, &ksev_launch_measure);

	/* Measurement causes a state transition, check that. */
	kvm_sev_ioctl(sev, KVM_SEV_GUEST_STATUS, &ksev_guest_status);
	TEST_ASSERT(ksev_guest_status.state == SEV_GSTATE_LSECRET,
		    "Unexpected guest state: %d", ksev_guest_status.state);
}

void sev_vm_launch_finish(struct sev_vm *sev)
{
	struct kvm_sev_guest_status ksev_status = {0};

	kvm_sev_ioctl(sev, KVM_SEV_GUEST_STATUS, &ksev_status);
	TEST_ASSERT(ksev_status.state == SEV_GSTATE_LUPDATE ||
		    ksev_status.state == SEV_GSTATE_LSECRET,
		    "Unexpected guest state: %d", ksev_status.state);

	kvm_sev_ioctl(sev, KVM_SEV_LAUNCH_FINISH, NULL);

	kvm_sev_ioctl(sev, KVM_SEV_GUEST_STATUS, &ksev_status);
	TEST_ASSERT(ksev_status.state == SEV_GSTATE_RUNNING,
		    "Unexpected guest state: %d", ksev_status.state);
}

int sev_get_pdh_info(struct sev_vm *sev, unsigned char **pdh, size_t *pdh_len,
		     unsigned char **cert_chain, size_t *cert_chain_len)
{
	struct sev_user_data_pdh_cert_export export = {};
	unsigned char *cert_chain_data = NULL;
	unsigned char *pdh_data = NULL;
	struct sev_issue_cmd arg;
	int ret;

	/* query the certificate length */

	arg.cmd = SEV_PDH_CERT_EXPORT;
	arg.data = (unsigned long)&export;
	ret = ioctl(sev->fd, SEV_ISSUE_CMD, &arg);
	if (ret < 0) {
		TEST_ASSERT(arg.error == SEV_RET_INVALID_LEN,
			    "failed to get PDH len ret=%d fw_err=%d",
			    ret, arg.error);
	}

	pdh_data = malloc(export.pdh_cert_len);
	cert_chain_data = malloc(export.cert_chain_len);
	export.pdh_cert_address = (unsigned long)pdh_data;
	export.cert_chain_address = (unsigned long)cert_chain_data;

	sev_ioctl(sev->fd, SEV_PDH_CERT_EXPORT, &export);

	*pdh = pdh_data;
	*pdh_len = export.pdh_cert_len;
	*cert_chain = cert_chain_data;
	*cert_chain_len = export.cert_chain_len;

	return 1;
}

static int sev_get_send_session_length(struct sev_vm *sev)
{
	struct kvm_sev_send_start start = {};
	struct kvm_sev_cmd arg = {0};
	int ret;

	arg.id = KVM_SEV_SEND_START;
	arg.sev_fd = sev->fd;
	arg.data = (__u64)&start;

	ret = ioctl(vm_get_fd(sev->vm), KVM_MEMORY_ENCRYPT_OP, &arg);
	TEST_ASSERT(arg.error == SEV_RET_INVALID_LEN,
		    "failed to get session length ret=%d fw_error=%d",
		    ret, arg.error);

	return start.session_len;
}

int sev_send_start(struct sev_vm *sev, u32 *policy, size_t *session_len,
		   unsigned char **session, size_t remote_pdh_len,
		   unsigned char *remote_pdh, size_t remote_plat_cert_len,
		   unsigned char *remote_plat_cert, size_t amd_cert_len,
		   unsigned char *amd_cert, size_t *source_pdh_len,
		   unsigned char **source_pdh)
{
	struct kvm_sev_send_start start = {};
	unsigned char *plat_cert = NULL;
	size_t plat_cert_len;

	start.pdh_cert_uaddr = (uintptr_t)remote_pdh;
	start.pdh_cert_len = remote_pdh_len;

	start.plat_certs_uaddr = (uintptr_t)remote_plat_cert;
	start.plat_certs_len = remote_plat_cert_len;

	start.amd_certs_uaddr = (uintptr_t)amd_cert;
	start.amd_certs_len = amd_cert_len;

	/* get the session length */
	*session_len = sev_get_send_session_length(sev);
	TEST_ASSERT(*session_len >= 0, "Unexpected session length");

	*session = malloc(*session_len);
	start.session_uaddr = (unsigned long)*session;
	start.session_len = *session_len;

	/* Get our PDH certificate */
	sev_get_pdh_info(sev, source_pdh, source_pdh_len,
			 &plat_cert, &plat_cert_len);

	kvm_sev_ioctl(sev, KVM_SEV_SEND_START, &start);

	*policy = start.policy;

	/* guest is now in SEV_STATE_SEND_UPDATE state */

	free(plat_cert);
	return 1;
}

static int sev_send_get_packet_len(struct sev_vm *sev)
{
	struct kvm_sev_send_update_data update = {};
	struct kvm_sev_cmd arg = {0};
	int ret;

	arg.id = KVM_SEV_SEND_UPDATE_DATA;
	arg.sev_fd = sev->fd;
	arg.data = (__u64)&update;

	ret = ioctl(vm_get_fd(sev->vm), KVM_MEMORY_ENCRYPT_OP, &arg);
	TEST_ASSERT(arg.error == SEV_RET_INVALID_LEN,
		    "failed to get session length ret=%d fw_error=%d",
		    ret, arg.error);

	return update.hdr_len;
}

void sev_send_update_data(struct sev_vm *sev, uint64_t hva, uint32_t size,
			  unsigned char **trans, unsigned char **send_packet_hdr,
			  size_t *send_packet_hdr_len, size_t *trans_len)
{
	struct kvm_sev_send_update_data update = { };

	/*
	 * If this is first call then query the packet header bytes and allocate
	 * the packet buffer.
	 */
	if (!*send_packet_hdr) {
		*send_packet_hdr_len = sev_send_get_packet_len(sev);
		*send_packet_hdr = malloc(*send_packet_hdr_len);
	}

	/* allocate transport buffer */
	*trans = malloc(size);

	update.hdr_uaddr = (uintptr_t)*send_packet_hdr;
	update.hdr_len = *send_packet_hdr_len;
	update.guest_uaddr = hva;
	update.guest_len = size;
	update.trans_uaddr = (uintptr_t)*trans;
	update.trans_len = size;

	if (!update.trans_uaddr || !update.guest_uaddr ||
	    !update.guest_len || !update.hdr_uaddr)
		pr_info("invalid args to send update data\n");

	kvm_sev_ioctl(sev, KVM_SEV_SEND_UPDATE_DATA, &update);

	*send_packet_hdr_len = update.hdr_len;
	*trans_len = update.trans_len;
}

int sev_receive_start(struct sev_vm *sev, u32 policy, size_t pdh_len,
		      unsigned char *pdh_cert, size_t session_len,
		      unsigned char *session)

{
	struct kvm_sev_receive_start start = {};

	start.handle = 0;

	/* get the source policy */
	start.policy = policy;

	/* get source PDH key */
	start.pdh_len = pdh_len;
	start.pdh_uaddr = (uintptr_t)pdh_cert;

	/* get source session data */
	start.session_len = session_len;
	start.session_uaddr = (uintptr_t)session;

	kvm_sev_ioctl(sev, KVM_SEV_RECEIVE_START, &start);

	/* guest is now in SEV_STATE_RECEIVE_UPDATE state */

	return 1;
}

void sev_receive_update_data(struct sev_vm *sev, uint64_t hva,
			     unsigned char *trans, unsigned char *hdr,
			     size_t trans_len, size_t hdr_len)
{
	struct kvm_sev_receive_update_data update = {};

	/* get packet header */
	update.hdr_len = hdr_len;
	update.hdr_uaddr = (uintptr_t)hdr;

	/* get transport buffer */
	update.trans_len = trans_len;
	update.trans_uaddr = (uintptr_t)trans;

	update.guest_uaddr = hva;
	update.guest_len = update.trans_len;

	if (!update.hdr_uaddr || !update.hdr_len ||
	    !update.guest_uaddr || !update.guest_len ||
	    !update.trans_uaddr || !update.trans_len)
		pr_info("receive update data, invalid parameter\n");

	kvm_sev_ioctl(sev, KVM_SEV_RECEIVE_UPDATE_DATA, &update);
}

void sev_send_finish(struct sev_vm *sev)
{
	kvm_sev_ioctl(sev, KVM_SEV_SEND_FINISH, 0);

}

void sev_receive_finish(struct sev_vm *sev)
{
	kvm_sev_ioctl(sev, KVM_SEV_RECEIVE_FINISH, 0);
}

void sev_migrate_vmsas(struct sev_vm *source_sev, struct sev_vm *remote_sev)
{
	vm_migrate_vcpus(sev_get_vm(source_sev), sev_get_vm(remote_sev));
}

void sev_migrate_data(struct sev_vm *source_sev, struct sev_vm *remote_sev)
{
	unsigned char *trans_buf, *send_packet_hdr = NULL;
	struct kvm_vm *remote_vm = remote_sev->vm;
	struct kvm_vm *source_vm = source_sev->vm;
	size_t send_packet_hdr_len, trans_len;
	uint8_t *remote_hva_ptr, *hva_ptr;
	struct sparsebit *enc_phy_pages;
	uint64_t memory_size;
	vm_paddr_t gpa_start;
	uint64_t remote_hva;
	sparsebit_idx_t pg;
	uint64_t gpa, hva;

	/* Only memslot 0 supported for now. */
	enc_phy_pages = vm_get_encrypted_phy_pages(source_vm, 0, &gpa_start, &memory_size);
	TEST_ASSERT(enc_phy_pages, "Unable to retrieve encrypted pages bitmap");
	for (pg = 0;  (pg < (memory_size / vm_get_page_size(source_vm))); pg++) {
		if (sparsebit_is_set(enc_phy_pages, pg)) {
			gpa = gpa_start + pg * vm_get_page_size(source_vm);
			hva = (__u64)addr_gpa2hva(source_vm, gpa);
			sev_send_update_data(source_sev,
					     hva, vm_get_page_size(source_vm),
					     &trans_buf, &send_packet_hdr,
					     &send_packet_hdr_len, &trans_len);
			remote_hva = (__u64)addr_gpa2hva(remote_vm, gpa);
			sev_receive_update_data(remote_sev,
						remote_hva, trans_buf, send_packet_hdr,
						trans_len, send_packet_hdr_len);
			free(trans_buf);
		} else {
			gpa = gpa_start + pg * vm_get_page_size(source_vm);
			hva_ptr = addr_gpa2hva(source_vm, gpa);
			remote_hva_ptr = addr_gpa2hva(remote_vm, gpa);
			memcpy(remote_hva_ptr, hva_ptr, vm_get_page_size(source_vm));
		}
	}

	sparsebit_free(&enc_phy_pages);
}

void sev_dbg_enc_dec(struct sev_vm *sev, uint8_t *dst,
		     const uint8_t *src, uint32_t len, bool write)
{
	struct kvm_sev_dbg dbg;

	dbg.src_uaddr = (unsigned long)src;
	dbg.dst_uaddr = (unsigned long)dst;
	dbg.len = len;

	kvm_sev_ioctl(sev,
		      write ? KVM_SEV_DBG_ENCRYPT : KVM_SEV_DBG_DECRYPT,
		      &dbg);
}

/* SEV-SNP VM implementation. */

struct sev_vm *sev_snp_vm_create(uint64_t policy, uint64_t npages)
{
	struct kvm_snp_init init = {0};
	struct sev_vm *sev;
	struct kvm_vm *vm;

	vm = vm_create(VM_MODE_DEFAULT, 0, O_RDWR);
	sev = sev_common_create(vm);
	if (!sev)
		return NULL;
	sev->snp_policy = policy | SNP_POLICY_RSVD;

	kvm_sev_ioctl(sev, KVM_SEV_SNP_INIT, &init);
	vm_set_memory_encryption(vm, true, true, sev->enc_bit);
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, 0, 0, npages, 0);
	sev_register_user_range(sev, addr_gpa2hva(vm, 0), npages * vm_get_page_size(vm));

	pr_info("SEV-SNP guest created, policy: 0x%lx, size: %lu KB\n",
		sev->snp_policy, npages * vm_get_page_size(vm) / 1024);

	return sev;
}

void sev_snp_vm_free(struct sev_vm *sev)
{
	kvm_vm_free(sev->vm);
	sev_common_free(sev);
}

void sev_snp_vm_launch(struct sev_vm *sev)
{
	struct kvm_sev_snp_launch_start launch_start = {0};
	struct kvm_sev_snp_launch_update launch_finish = {0};

	launch_start.policy = sev->snp_policy;
	kvm_sev_ioctl(sev, KVM_SEV_SNP_LAUNCH_START, &launch_start);

	sev_encrypt(sev);

	kvm_sev_ioctl(sev, KVM_SEV_SNP_LAUNCH_FINISH, &launch_finish);
}
