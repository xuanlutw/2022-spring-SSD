#include <linux/syscalls.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/mm_types.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/expose_pte.h>

#include <asm/syscall.h>
#include <asm/pgtable.h>

SYSCALL_DEFINE1(expose_pte, struct expose_pte_args __user *, args_user)
{
	struct expose_pte_args args;
	struct task_struct *task;
	struct mm_struct *target_mm, *current_mm;
	struct vm_area_struct *pte_vma;
	unsigned long *begin_fpt, *end_fpt, *fptp;
	unsigned long pte_count, pte_count_max;
	unsigned long begin_vaddr, end_vaddr, vaddr;

	unsigned long pgdi, pudi, pmdi;
	pgd_t *pgdp = NULL, pgd;
	pud_t *pudp = NULL, pud;
	pmd_t *pmdp = NULL, pmd;
	pte_t *ptep = NULL;

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
	target_mm = task->mm;
	if (!target_mm) {
		pr_info("Target task is a kernel thread.\n");
		return -EINVAL;
	}
	current_mm = current->mm;
	if (!current) {
		pr_info("Current task is a kernel thread.\n");
		return -EINVAL;
	}

	// Check pte. pte should be in one single vma (via mmap with MAP_SHARED)
	if ((args.begin_pte_vaddr > args.end_pte_vaddr) ||
			(args.end_pte_vaddr >= ((unsigned long)1 << 48))) {
		pr_info("pte value error.\n");
		return -EINVAL;
	}
	pte_vma = find_vma(target_mm, args.begin_pte_vaddr);
	if (!pte_vma || pte_vma->vm_start > args.begin_pte_vaddr) {
		pr_info("pte_vma error.\n");
		return -EINVAL;
	}
	pte_count_max = (args.end_pte_vaddr - args.begin_pte_vaddr) >> 12;

	// Check vaddr. Normalize its range.
	if ((args.begin_vaddr > args.end_vaddr) ||
			(args.end_vaddr >= ((unsigned long)1 << 48))) {
		pr_info("vaddr value error.\n");
		return -EINVAL;
	}
	begin_vaddr = args.begin_vaddr - (args.begin_vaddr & ((1 << 21) - 1));
	end_vaddr   = args.end_vaddr - 1;
	end_vaddr   = end_vaddr - (end_vaddr & ((1 << 21) - 1)) + (1 << 21);

	// Check fpt. Allocate space for fpt table
	if ((args.begin_fpt_vaddr > args.end_fpt_vaddr) ||
			(args.end_fpt_vaddr >= ((unsigned long)1 << 48))) {
		pr_info("fpt value error.\n");
		return -EINVAL;
	}
	begin_fpt = kmalloc(args.end_fpt_vaddr - args.begin_fpt_vaddr,
		GFP_ATOMIC);
	end_fpt = (unsigned long *)((unsigned long)begin_fpt +
			(args.end_fpt_vaddr - args.begin_fpt_vaddr));
	if (begin_fpt == NULL) {
		pr_info("kmalloc fail.\n");
		return -EFAULT;
	}
	memset(begin_fpt, 0, args.end_fpt_vaddr - args.begin_fpt_vaddr);

	// Traverse the page table.
	fptp      = begin_fpt;
	pte_count = 0;
	vaddr     = begin_vaddr;
	pgdi = pudi = pmdi = (1 << 15); // Impossible
	while (1) {
		if (vaddr >= end_vaddr ||
				fptp >= end_fpt ||
				pte_count >= pte_count_max)
			break;

		if (pgdi != pgd_index(vaddr)) {
			pgdi = pgd_index(vaddr);
			pgdp = pgd_offset(target_mm, vaddr);
			pgd = READ_ONCE(*pgdp);
			if (pgd_none(pgd) || pgd_bad(pgd)) {
				fptp  += (1 << 18);
				vaddr += ((unsigned long)1 << 39);
				pudi = pmdi = (1 << 15); // Impossible
				continue;
			}
		}

		if (pudi != pud_index(vaddr)) {
			pudi = pud_index(vaddr);
			pudp = pud_offset(pgdp, vaddr);
			pud = READ_ONCE(*pudp);
			if (pud_none(pud) || pud_bad(pud)) {
				fptp  += (1 << 9);
				vaddr += (1 << 30);
				pmdi = (1 << 15); // Impossible
				continue;
			}
		}

		if (pmdi != pmd_index(vaddr)) {
			pmdi = pmd_index(vaddr);
			pmdp = pmd_offset(pudp, vaddr);
			pmd = READ_ONCE(*pmdp);
			if (pmd_none(pmd) || pmd_bad(pmd)) {
				fptp  += 1;
				vaddr += (1 << 21);
				continue;
			}
		}

		// Remapping
		ptep  = pte_offset_map(pmdp, vaddr);
		*fptp = args.begin_pte_vaddr + (pte_count << 12);
		if (remap_pfn_range(pte_vma,
			pte_vma->vm_start + (pte_count << 12),
			virt_to_pfn(ptep), (1 << 12), pte_vma->vm_page_prot)) {
			pr_info("Remap fail\n");
		}
		fptp      += 1;
		pte_count += 1;
		vaddr     += (1 << 21);
	}

	// Restore result
	if (copy_to_user((void *)args.begin_fpt_vaddr, begin_fpt,
				args.end_fpt_vaddr - args.begin_fpt_vaddr)) {
		pr_info("Copy results to user fail.\n");
		kfree(begin_fpt);
		return -EINVAL;
	}

	kfree(begin_fpt);

	return 0;
}
