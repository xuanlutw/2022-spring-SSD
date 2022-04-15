#include <linux/syscalls.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/mm_types.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/expose_pte.h>

#include <asm/syscall.h>
#include <asm/pgtable.h>

int _expose_pte(struct mm_struct *mm, struct vm_area_struct *pte_vma,
	void **begin_fpt, void **end_fpt, void *begin_ptep, void *end_ptep,
	unsigned long begin_vaddr, unsigned long end_vaddr)
{
	int ret = 0;
	void **fpt;
	void *ptep;
	unsigned long vaddr;

	pgd_t *pgdp, pgd;
	pud_t *pudp, pud;
	pmd_t *pmdp, pmd;
	pte_t *ptep_p;

	// Traverse the page table.
	// Inefficiency lol.
    // Reference: arch/arm64/mm/fault.c#show_pte(unsigned long addr)
	fpt   = begin_fpt;
	ptep  = begin_ptep;
	vaddr = begin_vaddr;
	while (fpt < end_fpt &&
			vaddr < end_vaddr &&
			ptep < end_ptep) {
		pgdp = pgd_offset(mm, vaddr);
		pgd = READ_ONCE(*pgdp);
		if (pgd_none(pgd) || pgd_bad(pgd)) {
			fpt   += (1 << 18);
			vaddr += ((unsigned long)1 << 39);
			continue;
		}

		pudp = pud_offset(pgdp, vaddr);
		pud = READ_ONCE(*pudp);
		if (pud_none(pud) || pud_bad(pud)) {
			fpt   += (1 << 9);
			vaddr += (1 << 30);
			continue;
		}

		pmdp = pmd_offset(pudp, vaddr);
		pmd = READ_ONCE(*pmdp);
		if (pmd_none(pmd) || pmd_bad(pmd)) {
			fpt   += 1;
			vaddr += (1 << 21);
			continue;
		}

		// Remapping
		ptep_p = pte_offset_map(pmdp, vaddr);
		*fpt   = ptep;
		if (remap_pfn_range(pte_vma, (unsigned long)ptep,
			virt_to_pfn(ptep_p), 1 << 12, pte_vma->vm_page_prot)) {
			pr_info("Remap fail\n");
			ret = -EINVAL;
		}
		fpt   += 1;
		ptep  += (1 << 12);
		vaddr += (1 << 21);
	}

	return ret;
}

SYSCALL_DEFINE1(expose_pte, struct expose_pte_args __user *, args_user)
{
	struct expose_pte_args args;
	struct task_struct *task;
	struct mm_struct *mm;
	struct vm_area_struct *pte_vma;
	void **fpt;
	unsigned long fpt_len;
	unsigned long align_begin_vaddr, align_end_vaddr;
	int ret;

	// Get args.
	if (copy_from_user(&args, args_user, sizeof(struct expose_pte_args))) {
		pr_info("Copy args from user fail.\n");
		return -EINVAL;
	}

	// Check pid. Get task/mm from pid.
	task = find_task_by_pid_ns(args.pid, &init_pid_ns);
	if (!task) {
		pr_info("Invalid pid.\n");
		return -EINVAL;
	}
	mm = task->mm;
	if (!mm) {
		pr_info("Target task is a kernel thread.\n");
		return -EINVAL;
	}

	// Check pte value.
	if ((args.begin_pte_vaddr & ((1 << 12) - 1)) ||
			(args.end_pte_vaddr & ((1 << 12) - 1)) ||
			(args.begin_pte_vaddr > args.end_pte_vaddr) ||
			(args.end_pte_vaddr >= ((unsigned long)1 << 48))) {
		pr_info("pte value error.\n");
		return -EINVAL;
	}

	// Check pte in a single vma (via mmap with MAP_SHARED).
	if (!(current->mm)) {
		pr_info("Current task is a kernel thread.\n");
		return -EINVAL;
	}
	pte_vma = find_vma(current->mm, args.begin_pte_vaddr);
	if (!pte_vma || pte_vma->vm_start > args.begin_pte_vaddr) {
		pr_info("pte_vma error.\n");
		return -EINVAL;
	}

	// Check vaddr value and align pmd.
	if ((args.begin_vaddr > args.end_vaddr) ||
			(args.end_vaddr >= ((unsigned long)1 << 48))) {
		pr_info("vaddr value error.\n");
		return -EINVAL;
	}
	align_begin_vaddr = args.begin_vaddr -
		(args.begin_vaddr & ((1 << 21) - 1));
	align_end_vaddr   = args.end_vaddr - 1;
	align_end_vaddr   = align_end_vaddr -
		(align_end_vaddr & ((1 << 21) - 1)) + (1 << 21);

	// Check fpt value.
	if ((args.begin_fpt_vaddr > args.end_fpt_vaddr) ||
			(args.end_fpt_vaddr >= ((unsigned long)1 << 48))) {
		pr_info("fpt value error.\n");
		return -EINVAL;
	}
	fpt_len = args.end_fpt_vaddr - args.begin_fpt_vaddr;

	// Allocate space for fpt table
	fpt = kmalloc(args.end_fpt_vaddr - args.begin_fpt_vaddr, GFP_ATOMIC);
	if (fpt == NULL) {
		pr_info("Allocate fpt fail.\n");
		return -EINVAL;
	}
	memset(fpt, 0, fpt_len);

	ret = _expose_pte(mm, pte_vma, fpt, fpt + fpt_len,
		(void *)args.begin_pte_vaddr, (void *)args.end_pte_vaddr,
		align_begin_vaddr, align_end_vaddr);

	// Restore result
	if (copy_to_user((void *)args.begin_fpt_vaddr, fpt, fpt_len)) {
		pr_info("Copy results to user fail.\n");
		ret = -EINVAL;
	}

	kfree(fpt);
	return ret;
}
