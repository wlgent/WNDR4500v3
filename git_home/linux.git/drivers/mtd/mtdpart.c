/*
 * Simple MTD partitioning layer
 *
 * (C) 2000 Nicolas Pitre <nico@cam.org>
 *
 * This code is GPL
 *
 * 	02-21-2002	Thomas Gleixner <gleixner@autronix.de>
 *			added support for read_oob, write_oob
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/kmod.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/partitions.h>
#include <linux/mtd/compatmac.h>
#include <linux/root_dev.h>
#include <linux/magic.h>

#define DNI_PARTITION_MAPPING	1

#ifdef DNI_PARTITION_MAPPING
/* 
 * definicate one mapping table for squashfs
 * partition, because squashfs do not know bad block.
 * So we have to do the valid mapping between logic block
 * and phys block.
 */

#include <linux/mtd/nand.h>

#define MAX_MAPPING_COUNT	1

struct logic_phys_map {
    struct mtd_info *part_mtd;	/* Mapping partition mtd */
    unsigned *map_table;	/* Mapping from logic block to phys block */
    unsigned nBlock;		/* Logic block number */
};

static struct logic_phys_map *logic_phys_mapping[MAX_MAPPING_COUNT];
static int mapping_count = -1;
#endif

static int relocate_count = 0;

#ifdef CONFIG_MTD_ROOTFS_SPLIT || DNI_PARTITION_MAPPING
struct squashfs_super_block {
	__le32 s_magic;
	__le32 pad0[9];
	__le64 bytes_used;
};
#endif

/* Our partition linked list */
static LIST_HEAD(mtd_partitions);

/* Our partition node structure */
struct mtd_part {
	struct mtd_info mtd;
	struct mtd_info *master;
	uint64_t offset;
	struct list_head list;
};

/*
 * Given a pointer to the MTD object in the mtd_part structure, we can retrieve
 * the pointer to that structure with this macro.
 */
#define PART(x)  ((struct mtd_part *)(x))
#define IS_PART(mtd) (mtd->read == part_read)

/*
 * MTD methods which simply translate the effective address and pass through
 * to the _real_ device.
 */

static int part_read(struct mtd_info *mtd, loff_t from, size_t len,
		size_t *retlen, u_char *buf)
{
	struct mtd_part *part = PART(mtd);
	struct mtd_ecc_stats stats;
	int res;

	stats = part->master->ecc_stats;

#ifdef DNI_PARTITION_MAPPING
	/* Calculate physical address from the partition mapping */
	unsigned logic_b, phys_b;
	int i;

	if (mapping_count > 0) {
		for (i = 0; i < MAX_MAPPING_COUNT; i++) {
			if (logic_phys_mapping[i] && logic_phys_mapping[i]->part_mtd == mtd) {
				/* remap from logic block to physical block */
				logic_b = from >> mtd->erasesize_shift;
				if (logic_b < logic_phys_mapping[i]->nBlock) {
					phys_b = logic_phys_mapping[i]->map_table[logic_b];
					from = (phys_b << mtd->erasesize_shift) | (from & (mtd->erasesize - 1));
				} else {
					/* the offset is bigger than good block range, don't read data */
					*retlen = 0;
					return -EINVAL;
				}
			}
		}
	}
#endif

	if (from >= mtd->size)
		len = 0;
	else if (from + len > mtd->size)
		len = mtd->size - from;
	res = part->master->read(part->master, from + part->offset,
				   len, retlen, buf);
	if (unlikely(res)) {
		if (res == -EUCLEAN)
			mtd->ecc_stats.corrected += part->master->ecc_stats.corrected - stats.corrected;
		if (res == -EBADMSG)
			mtd->ecc_stats.failed += part->master->ecc_stats.failed - stats.failed;
	}
	return res;
}

static int part_point(struct mtd_info *mtd, loff_t from, size_t len,
		size_t *retlen, void **virt, resource_size_t *phys)
{
	struct mtd_part *part = PART(mtd);
	if (from >= mtd->size)
		len = 0;
	else if (from + len > mtd->size)
		len = mtd->size - from;
	return part->master->point (part->master, from + part->offset,
				    len, retlen, virt, phys);
}

static void part_unpoint(struct mtd_info *mtd, loff_t from, size_t len)
{
	struct mtd_part *part = PART(mtd);

	part->master->unpoint(part->master, from + part->offset, len);
}

static unsigned long part_get_unmapped_area(struct mtd_info *mtd,
					    unsigned long len,
					    unsigned long offset,
					    unsigned long flags)
{
	struct mtd_part *part = PART(mtd);

	offset += part->offset;
	return part->master->get_unmapped_area(part->master, len, offset,
					       flags);
}

static int part_read_oob(struct mtd_info *mtd, loff_t from,
		struct mtd_oob_ops *ops)
{
	struct mtd_part *part = PART(mtd);
	int res;

	if (from >= mtd->size)
		return -EINVAL;
	if (ops->datbuf && from + ops->len > mtd->size)
		return -EINVAL;
	res = part->master->read_oob(part->master, from + part->offset, ops);

	if (unlikely(res)) {
		if (res == -EUCLEAN)
			mtd->ecc_stats.corrected++;
		if (res == -EBADMSG)
			mtd->ecc_stats.failed++;
	}
	return res;
}

static int part_read_user_prot_reg(struct mtd_info *mtd, loff_t from,
		size_t len, size_t *retlen, u_char *buf)
{
	struct mtd_part *part = PART(mtd);
	return part->master->read_user_prot_reg(part->master, from,
					len, retlen, buf);
}

static int part_get_user_prot_info(struct mtd_info *mtd,
		struct otp_info *buf, size_t len)
{
	struct mtd_part *part = PART(mtd);
	return part->master->get_user_prot_info(part->master, buf, len);
}

static int part_read_fact_prot_reg(struct mtd_info *mtd, loff_t from,
		size_t len, size_t *retlen, u_char *buf)
{
	struct mtd_part *part = PART(mtd);
	return part->master->read_fact_prot_reg(part->master, from,
					len, retlen, buf);
}

static int part_get_fact_prot_info(struct mtd_info *mtd, struct otp_info *buf,
		size_t len)
{
	struct mtd_part *part = PART(mtd);
	return part->master->get_fact_prot_info(part->master, buf, len);
}

static int part_write(struct mtd_info *mtd, loff_t to, size_t len,
		size_t *retlen, const u_char *buf)
{
	struct mtd_part *part = PART(mtd);
	if (!(mtd->flags & MTD_WRITEABLE))
		return -EROFS;
	if (to >= mtd->size)
		len = 0;
	else if (to + len > mtd->size)
		len = mtd->size - to;
	return part->master->write(part->master, to + part->offset,
				    len, retlen, buf);
}

static int part_panic_write(struct mtd_info *mtd, loff_t to, size_t len,
		size_t *retlen, const u_char *buf)
{
	struct mtd_part *part = PART(mtd);
	if (!(mtd->flags & MTD_WRITEABLE))
		return -EROFS;
	if (to >= mtd->size)
		len = 0;
	else if (to + len > mtd->size)
		len = mtd->size - to;
	return part->master->panic_write(part->master, to + part->offset,
				    len, retlen, buf);
}

static int part_write_oob(struct mtd_info *mtd, loff_t to,
		struct mtd_oob_ops *ops)
{
	struct mtd_part *part = PART(mtd);

	if (!(mtd->flags & MTD_WRITEABLE))
		return -EROFS;

	if (to >= mtd->size)
		return -EINVAL;
	if (ops->datbuf && to + ops->len > mtd->size)
		return -EINVAL;
	return part->master->write_oob(part->master, to + part->offset, ops);
}

static int part_write_user_prot_reg(struct mtd_info *mtd, loff_t from,
		size_t len, size_t *retlen, u_char *buf)
{
	struct mtd_part *part = PART(mtd);
	return part->master->write_user_prot_reg(part->master, from,
					len, retlen, buf);
}

static int part_lock_user_prot_reg(struct mtd_info *mtd, loff_t from,
		size_t len)
{
	struct mtd_part *part = PART(mtd);
	return part->master->lock_user_prot_reg(part->master, from, len);
}

static int part_writev(struct mtd_info *mtd, const struct kvec *vecs,
		unsigned long count, loff_t to, size_t *retlen)
{
	struct mtd_part *part = PART(mtd);
	if (!(mtd->flags & MTD_WRITEABLE))
		return -EROFS;
	return part->master->writev(part->master, vecs, count,
					to + part->offset, retlen);
}

static int part_erase(struct mtd_info *mtd, struct erase_info *instr)
{
	struct mtd_part *part = PART(mtd);
	int ret;
	if (!(mtd->flags & MTD_WRITEABLE))
		return -EROFS;
	if (instr->addr >= mtd->size)
		return -EINVAL;
	instr->addr += part->offset;
	ret = part->master->erase(part->master, instr);
	if (ret) {
		if (instr->fail_addr != MTD_FAIL_ADDR_UNKNOWN)
			instr->fail_addr -= part->offset;
		instr->addr -= part->offset;
	}
	return ret;
}

void mtd_erase_callback(struct erase_info *instr)
{
	if (instr->mtd->erase == part_erase) {
		struct mtd_part *part = PART(instr->mtd);

		if (instr->fail_addr != MTD_FAIL_ADDR_UNKNOWN)
			instr->fail_addr -= part->offset;
		instr->addr -= part->offset;
	}
	if (instr->callback)
		instr->callback(instr);
}
EXPORT_SYMBOL_GPL(mtd_erase_callback);

static int part_lock(struct mtd_info *mtd, loff_t ofs, uint64_t len)
{
	struct mtd_part *part = PART(mtd);
	if ((len + ofs) > mtd->size)
		return -EINVAL;
	return part->master->lock(part->master, ofs + part->offset, len);
}

static int part_unlock(struct mtd_info *mtd, loff_t ofs, uint64_t len)
{
	struct mtd_part *part = PART(mtd);
	if ((len + ofs) > mtd->size)
		return -EINVAL;
	return part->master->unlock(part->master, ofs + part->offset, len);
}

static void part_sync(struct mtd_info *mtd)
{
	struct mtd_part *part = PART(mtd);
	part->master->sync(part->master);
}

static int part_suspend(struct mtd_info *mtd)
{
	struct mtd_part *part = PART(mtd);
	return part->master->suspend(part->master);
}

static void part_resume(struct mtd_info *mtd)
{
	struct mtd_part *part = PART(mtd);
	part->master->resume(part->master);
}

static int part_block_isbad(struct mtd_info *mtd, loff_t ofs)
{
	struct mtd_part *part = PART(mtd);
	if (ofs >= mtd->size)
		return -EINVAL;
	ofs += part->offset;
	return part->master->block_isbad(part->master, ofs);
}

static int part_block_markbad(struct mtd_info *mtd, loff_t ofs)
{
	struct mtd_part *part = PART(mtd);
	int res;

	if (!(mtd->flags & MTD_WRITEABLE))
		return -EROFS;
	if (ofs >= mtd->size)
		return -EINVAL;
	ofs += part->offset;
	res = part->master->block_markbad(part->master, ofs);
	if (!res)
		mtd->ecc_stats.badblocks++;
	return res;
}

#ifdef DNI_PARTITION_MAPPING
/*
 * This function search squashfs magic data, and record offset and bad block values
 */
static int find_rootfs_header(struct mtd_info *master, struct mtd_info *mtd, uint64_t *offset, int *bad_blocks)
{
	struct mtd_part *part = PART(mtd);
	struct squashfs_super_block sb;
	int len, res;

	while (*offset < mtd->size) {
		if (mtd->block_isbad && mtd->block_isbad(part, *offset)) {
			*bad_blocks++;
			*offset += mtd->erasesize;
			continue;
		}

		res = master->read(master, *offset + part->offset, sizeof(sb), &len, (void *) &sb);
		if (res || (len != sizeof(sb))) {
			printk(KERN_ALERT "%s: error occured while reading from partition \"%s\" of \"%s\"!\n",
					__func__, mtd->name, master->name);
			return -1;
		}

		if (SQUASHFS_MAGIC == le32_to_cpu(sb.s_magic)) {
			printk(KERN_INFO "mtd: find squashfs magic at 0x%llx of \"%s\"\n",
					*offset + part->offset, master->name);
			break;
		}

		*offset += mtd->erasesize;
	}

	if (*offset >= mtd->size) {
		printk(KERN_ALERT "%s: no squashfs found in partition \"%s\" of \"%s\"!\n",
				__func__, mtd->name, master->name);
		return -1;
	}

	return 0;
}

/*
 * This function create a partition mapping from logic block to phys block
 */
static int create_partition_mapping (struct mtd_info *part_mtd)
{
	struct logic_phys_map *map;
	int index;
	loff_t offset;
	unsigned logical_b, phys_b;

	if (!part_mtd) {
		printk(KERN_ALERT "null mtd or it is no nand chip!\n");
		return -1;
	}

	if (mapping_count < 0) {
		/* Init the part mapping table when this function called first time */
		memset(logic_phys_mapping, 0, sizeof(struct logic_phys_map *) * MAX_MAPPING_COUNT);
		mapping_count = 0;
	}

	for (index = 0; index < MAX_MAPPING_COUNT; index++) {
		if (logic_phys_mapping[index] == NULL)
			break;
	}

	if (index >= MAX_MAPPING_COUNT) {
		printk(KERN_ALERT "partition mapping is full!\n");
		return -1;
	}

	map = kmalloc(sizeof(struct logic_phys_map), GFP_KERNEL);
	if (!map) {
		printk(KERN_ALERT "memory allocation error while creating partitions mapping for %s\n",
		       part_mtd->name);
		return -1;
	}

	map->map_table = kmalloc(sizeof(unsigned) * (part_mtd->size >> part_mtd->erasesize_shift), GFP_KERNEL);
	if (!map->map_table) {
		printk(KERN_ALERT "memory allocation error while creating partitions mapping for %s\n",
		       part_mtd->name);
		kfree(map);
		return -1;
	}

	memset(map->map_table, 0xFF, sizeof(unsigned) * (part_mtd->size >> part_mtd->erasesize_shift));

	/* Create partition mapping table from logic block to phys block */
	logical_b = 0;
	for (offset = 0; offset < part_mtd->size; offset += part_mtd->erasesize) {
		if (part_mtd->block_isbad && part_mtd->block_isbad(part_mtd, offset))
			continue;

		phys_b = offset >> part_mtd->erasesize_shift;
		map->map_table[logical_b] = phys_b;
		//printk(KERN_INFO "part[%s]: logic[%u]=phys[%u]\n", part_mtd->name, logical_b, phys_b);
		logical_b++;
	}

	map->nBlock = logical_b;
	map->part_mtd = part_mtd;
	logic_phys_mapping[index] = map;
	mapping_count++;

	return 0;
}

/*
 * This function delete all the partition mapping from logic block to phys block
 */
static void del_partition_mapping(struct mtd_info *part_mtd)
{
	int index;
	struct logic_phys_map *map;

	if (mapping_count > 0) {
		for (index = 0; index < MAX_MAPPING_COUNT; index++) {
			map = logic_phys_mapping[index];
			if (map && map->part_mtd == part_mtd) {
				kfree(map->map_table);
				kfree(map);
				logic_phys_mapping[index] = NULL;
				mapping_count--;
			}
		}
	}
}
#endif

/*
 * This function unregisters and destroy all slave MTD objects which are
 * attached to the given master MTD object.
 */

int del_mtd_partitions(struct mtd_info *master)
{
	struct mtd_part *slave, *next;

	list_for_each_entry_safe(slave, next, &mtd_partitions, list)
		if (slave->master == master) {
#ifdef DNI_PARTITION_MAPPING
			/* Free partition mapping if created */
			del_partition_mapping(&slave->mtd);
#endif
			list_del(&slave->list);
			del_mtd_device(&slave->mtd);
			kfree(slave);
		}

	return 0;
}
EXPORT_SYMBOL(del_mtd_partitions);

static struct mtd_part *add_one_partition(struct mtd_info *master,
		const struct mtd_partition *part, int partno,
		uint64_t cur_offset)
{
	struct mtd_part *slave;

	/* allocate the partition structure */
	slave = kzalloc(sizeof(*slave), GFP_KERNEL);
	if (!slave) {
		printk(KERN_ERR"memory allocation error while creating partitions for \"%s\"\n",
			master->name);
		del_mtd_partitions(master);
		return NULL;
	}
	list_add(&slave->list, &mtd_partitions);

	/* set up the MTD object for this partition */
	slave->mtd.type = master->type;
	slave->mtd.flags = master->flags & ~part->mask_flags;
	slave->mtd.size = part->size;
	slave->mtd.writesize = master->writesize;
	slave->mtd.oobsize = master->oobsize;
	slave->mtd.oobavail = master->oobavail;
	slave->mtd.subpage_sft = master->subpage_sft;

	slave->mtd.name = part->name;
	slave->mtd.owner = master->owner;
	slave->mtd.backing_dev_info = master->backing_dev_info;

	/* NOTE:  we don't arrange MTDs as a tree; it'd be error-prone
	 * to have the same data be in two different partitions.
	 */
	slave->mtd.dev.parent = master->dev.parent;

	slave->mtd.read = part_read;
	slave->mtd.write = part_write;

	if (master->panic_write)
		slave->mtd.panic_write = part_panic_write;

	if (master->point && master->unpoint) {
		slave->mtd.point = part_point;
		slave->mtd.unpoint = part_unpoint;
	}

	if (master->get_unmapped_area)
		slave->mtd.get_unmapped_area = part_get_unmapped_area;
	if (master->read_oob)
		slave->mtd.read_oob = part_read_oob;
	if (master->write_oob)
		slave->mtd.write_oob = part_write_oob;
	if (master->read_user_prot_reg)
		slave->mtd.read_user_prot_reg = part_read_user_prot_reg;
	if (master->read_fact_prot_reg)
		slave->mtd.read_fact_prot_reg = part_read_fact_prot_reg;
	if (master->write_user_prot_reg)
		slave->mtd.write_user_prot_reg = part_write_user_prot_reg;
	if (master->lock_user_prot_reg)
		slave->mtd.lock_user_prot_reg = part_lock_user_prot_reg;
	if (master->get_user_prot_info)
		slave->mtd.get_user_prot_info = part_get_user_prot_info;
	if (master->get_fact_prot_info)
		slave->mtd.get_fact_prot_info = part_get_fact_prot_info;
	if (master->sync)
		slave->mtd.sync = part_sync;
	if (!partno && !master->dev.class && master->suspend && master->resume) {
			slave->mtd.suspend = part_suspend;
			slave->mtd.resume = part_resume;
	}
	if (master->writev)
		slave->mtd.writev = part_writev;
	if (master->lock)
		slave->mtd.lock = part_lock;
	if (master->unlock)
		slave->mtd.unlock = part_unlock;
	if (master->block_isbad)
		slave->mtd.block_isbad = part_block_isbad;
	if (master->block_markbad)
		slave->mtd.block_markbad = part_block_markbad;
	slave->mtd.erase = part_erase;
	slave->master = master;
	slave->offset = part->offset;

	if (slave->offset == MTDPART_OFS_APPEND)
		slave->offset = cur_offset;
	if (slave->offset == MTDPART_OFS_NXTBLK) {
		slave->offset = cur_offset;
		if (mtd_mod_by_eb(cur_offset, master) != 0) {
			/* Round up to next erasesize */
			slave->offset = (mtd_div_by_eb(cur_offset, master) + 1) * master->erasesize;
			printk(KERN_NOTICE "Moving partition %d: "
			       "0x%012llx -> 0x%012llx\n", partno,
			       (unsigned long long)cur_offset, (unsigned long long)slave->offset);
		}
	}
	if (slave->mtd.size == MTDPART_SIZ_FULL)
		slave->mtd.size = master->size - slave->offset;

	printk(KERN_NOTICE "0x%012llx-0x%012llx : \"%s\"\n", (unsigned long long)slave->offset,
		(unsigned long long)(slave->offset + slave->mtd.size), slave->mtd.name);

	/* let's do some sanity checks */
	if (slave->offset >= master->size) {
		/* let's register it anyway to preserve ordering */
		slave->offset = 0;
		slave->mtd.size = 0;
		printk(KERN_ERR"mtd: partition \"%s\" is out of reach -- disabled\n",
			part->name);
		goto out_register;
	}
	if (slave->offset + slave->mtd.size > master->size) {
		slave->mtd.size = master->size - slave->offset;
		printk(KERN_WARNING"mtd: partition \"%s\" extends beyond the end of device \"%s\" -- size truncated to %#llx\n",
			part->name, master->name, (unsigned long long)slave->mtd.size);
	}
	if (master->numeraseregions > 1) {
		/* Deal with variable erase size stuff */
		int i, max = master->numeraseregions;
		u64 end = slave->offset + slave->mtd.size;
		struct mtd_erase_region_info *regions = master->eraseregions;

		/* Find the first erase regions which is part of this
		 * partition. */
		for (i = 0; i < max && regions[i].offset <= slave->offset; i++)
			;
		/* The loop searched for the region _behind_ the first one */
		i--;

		/* Pick biggest erasesize */
		for (; i < max && regions[i].offset < end; i++) {
			if (slave->mtd.erasesize < regions[i].erasesize) {
				slave->mtd.erasesize = regions[i].erasesize;
			}
		}
		BUG_ON(slave->mtd.erasesize == 0);
	} else {
		/* Single erase size */
		slave->mtd.erasesize = master->erasesize;
	}

	if ((slave->mtd.flags & MTD_WRITEABLE) &&
	    mtd_mod_by_eb(slave->offset, &slave->mtd)) {
		/* Doesn't start on a boundary of major erase size */
		/* FIXME: Let it be writable if it is on a boundary of
		 * _minor_ erase size though */
		slave->mtd.flags &= ~MTD_WRITEABLE;
		printk(KERN_WARNING"mtd: partition \"%s\" doesn't start on an erase block boundary -- force read-only\n",
			part->name);
	}
	if ((slave->mtd.flags & MTD_WRITEABLE) &&
	    mtd_mod_by_eb(slave->mtd.size, &slave->mtd)) {
		slave->mtd.flags &= ~MTD_WRITEABLE;
		printk(KERN_WARNING"mtd: partition \"%s\" doesn't end on an erase block -- force read-only\n",
			part->name);
	}

	slave->mtd.ecclayout = master->ecclayout;
	if (master->block_isbad) {
		uint64_t offs = 0;

		while (offs < slave->mtd.size) {
			if (master->block_isbad(master,
						offs + slave->offset))
				slave->mtd.ecc_stats.badblocks++;
			offs += slave->mtd.erasesize;
		}
	}

out_register:
	/* register our partition */
	add_mtd_device(&slave->mtd);

#ifdef DNI_PARTITION_MAPPING
	/* Search rootfs header and reset the offset and size of rootfs partition */
	uint64_t rootfs_offset = 0;
	int bad_blocks = 0;
	if (slave->mtd.name && !strcmp(slave->mtd.name, "rootfs") &&
	    !(find_rootfs_header(master, &slave->mtd, &rootfs_offset, &bad_blocks))) {
		slave->offset += rootfs_offset;
		slave->mtd.size -= rootfs_offset;
		if (master->block_isbad)
			slave->mtd.ecc_stats.badblocks -= bad_blocks;

		printk(KERN_INFO "the correct location of partition \"%s\": 0x%012llx-0x%012llx\n", slave->mtd.name,
		       (unsigned long long)slave->offset, (unsigned long long)(slave->offset + slave->mtd.size));

		/* Build partition mapping for rootfs partition */
		create_partition_mapping(&slave->mtd);
	}
#endif

	return slave;
}

#ifdef CONFIG_MTD_ROOTFS_SPLIT
#define ROOTFS_SPLIT_NAME "rootfs_data"
#define ROOTFS_REMOVED_NAME "<removed>"


static int split_squashfs(struct mtd_info *master, int offset, int *split_offset)
{
	struct squashfs_super_block sb;
	int len, ret;

	ret = master->read(master, offset, sizeof(sb), &len, (void *) &sb);
	if (ret || (len != sizeof(sb))) {
		printk(KERN_ALERT "split_squashfs: error occured while reading "
			"from \"%s\"\n", master->name);
		return -EINVAL;
	}

	if (SQUASHFS_MAGIC != le32_to_cpu(sb.s_magic) ) {
		printk(KERN_ALERT "split_squashfs: no squashfs found in \"%s\"\n",
			master->name);
		*split_offset = 0;
		return 0;
	}

	if (le64_to_cpu((sb.bytes_used)) <= 0) {
		printk(KERN_ALERT "split_squashfs: squashfs is empty in \"%s\"\n",
			master->name);
		*split_offset = 0;
		return 0;
	}

	len = (u32) le64_to_cpu(sb.bytes_used);
	len += (offset & 0x000fffff);
	len +=  (master->erasesize - 1);
	len &= ~(master->erasesize - 1);
	len -= (offset & 0x000fffff);
	*split_offset = offset + len;

	return 0;
}

static int split_rootfs_data(struct mtd_info *master, struct mtd_info *rpart, const struct mtd_partition *part)
{
	struct mtd_partition *dpart;
	struct mtd_part *slave = NULL;
	int split_offset = 0;
	int ret;

#ifdef DNI_PARTITION_MAPPING
	struct mtd_part *tmp_part = PART(rpart);
	ret = split_squashfs(master, tmp_part->offset, &split_offset);
#else
	ret = split_squashfs(master, part->offset, &split_offset);
#endif
	if (ret)
		return ret;

	if (split_offset <= 0)
		return 0;

	dpart = kmalloc(sizeof(*part)+sizeof(ROOTFS_SPLIT_NAME)+1, GFP_KERNEL);
	if (dpart == NULL) {
		printk(KERN_INFO "split_squashfs: no memory for partition \"%s\"\n",
			ROOTFS_SPLIT_NAME);
		return -ENOMEM;
	}

	memcpy(dpart, part, sizeof(*part));
	dpart->name = (unsigned char *)&dpart[1];
	strcpy(dpart->name, ROOTFS_SPLIT_NAME);

	dpart->size -= split_offset - dpart->offset;
	dpart->offset = split_offset;

	if (dpart == NULL)
		return 1;

	printk(KERN_INFO "mtd: partition \"%s\" created automatically, ofs=%llX, len=%llX \n",
		ROOTFS_SPLIT_NAME, dpart->offset, dpart->size);

	slave = add_one_partition(master, dpart, 0, split_offset);
	if (!slave) {
		kfree(dpart);
		return -ENOMEM;
	}
	rpart->split = &slave->mtd;

	return 0;
}

static int refresh_rootfs_split(struct mtd_info *mtd)
{
	struct mtd_partition tpart;
	struct mtd_part *part;
	char *name;
	//int index = 0;
	int offset, size;
	int ret;

	part = PART(mtd);

	/* check for the new squashfs offset first */
	ret = split_squashfs(part->master, part->offset, &offset);
	if (ret)
		return ret;

	if ((offset > 0) && !mtd->split) {
		printk(KERN_INFO "%s: creating new split partition for \"%s\"\n", __func__, mtd->name);
		/* if we don't have a rootfs split partition, create a new one */
		tpart.name = (char *) mtd->name;
		tpart.size = mtd->size;
		tpart.offset = part->offset;

		return split_rootfs_data(part->master, &part->mtd, &tpart);
	} else if ((offset > 0) && mtd->split) {
		/* update the offsets of the existing partition */
		size = mtd->size + part->offset - offset;

		part = PART(mtd->split);
		part->offset = offset;
		part->mtd.size = size;
		printk(KERN_INFO "%s: %s partition \"" ROOTFS_SPLIT_NAME "\", offset: 0x%06x (0x%06x)\n",
			__func__, (!strcmp(part->mtd.name, ROOTFS_SPLIT_NAME) ? "updating" : "creating"),
			(u32) part->offset, (u32) part->mtd.size);
		name = kmalloc(sizeof(ROOTFS_SPLIT_NAME) + 1, GFP_KERNEL);
		strcpy(name, ROOTFS_SPLIT_NAME);
		part->mtd.name = name;
	} else if ((offset <= 0) && mtd->split) {
		printk(KERN_INFO "%s: removing partition \"%s\"\n", __func__, mtd->split->name);

		/* mark existing partition as removed */
		part = PART(mtd->split);
		name = kmalloc(sizeof(ROOTFS_SPLIT_NAME) + 1, GFP_KERNEL);
		strcpy(name, ROOTFS_REMOVED_NAME);
		part->mtd.name = name;
		part->offset = 0;
		part->mtd.size = 0;
	}

	return 0;
}
#endif /* CONFIG_MTD_ROOTFS_SPLIT */

/*
 * This function, given a master MTD object and a partition table, creates
 * and registers slave MTD objects which are bound to the master according to
 * the partition definitions.
 *
 * We don't register the master, or expect the caller to have done so,
 * for reasons of data integrity.
 */

int add_mtd_partitions(struct mtd_info *master,
		       const struct mtd_partition *parts,
		       int nbparts)
{
	struct mtd_part *slave;
	uint64_t cur_offset = 0;
	int i, ret;

	printk(KERN_NOTICE "Creating %d MTD partitions on \"%s\":\n", nbparts, master->name);

	for (i = 0; i < nbparts; i++) {
		slave = add_one_partition(master, parts + i, i, cur_offset);
		if (!slave)
			return -ENOMEM;

		if (!strcmp(parts[i].name, "rootfs")) {
#ifdef CONFIG_MTD_ROOTFS_ROOT_DEV
			if (ROOT_DEV == 0) {
				printk(KERN_NOTICE "mtd: partition \"rootfs\" "
					"set to be root filesystem\n");
				ROOT_DEV = MKDEV(MTD_BLOCK_MAJOR, i+relocate_count);
			}
#endif
#ifdef CONFIG_MTD_ROOTFS_SPLIT
			ret = split_rootfs_data(master, &slave->mtd, &parts[i]);
			/* if (ret == 0)
				j++; */
#endif
		}
		cur_offset = slave->offset + slave->mtd.size;
	}

	relocate_count += nbparts;

	return 0;
}
EXPORT_SYMBOL(add_mtd_partitions);

int refresh_mtd_partitions(struct mtd_info *mtd)
{
	int ret = 0;

	if (IS_PART(mtd)) {
		struct mtd_part *part;
		struct mtd_info *master;

		part = PART(mtd);
		master = part->master;
		if (master->refresh_device)
			ret = master->refresh_device(master);
	}

	if (!ret && mtd->refresh_device)
		ret = mtd->refresh_device(mtd);

#ifdef CONFIG_MTD_ROOTFS_SPLIT
	if (!ret && IS_PART(mtd) && !strcmp(mtd->name, "rootfs"))
		refresh_rootfs_split(mtd);
#endif

	return 0;
}
EXPORT_SYMBOL_GPL(refresh_mtd_partitions);

static DEFINE_SPINLOCK(part_parser_lock);
static LIST_HEAD(part_parsers);

static struct mtd_part_parser *get_partition_parser(const char *name)
{
	struct mtd_part_parser *p, *ret = NULL;

	spin_lock(&part_parser_lock);

	list_for_each_entry(p, &part_parsers, list)
		if (!strcmp(p->name, name) && try_module_get(p->owner)) {
			ret = p;
			break;
		}

	spin_unlock(&part_parser_lock);

	return ret;
}

int register_mtd_parser(struct mtd_part_parser *p)
{
	spin_lock(&part_parser_lock);
	list_add(&p->list, &part_parsers);
	spin_unlock(&part_parser_lock);

	return 0;
}
EXPORT_SYMBOL_GPL(register_mtd_parser);

int deregister_mtd_parser(struct mtd_part_parser *p)
{
	spin_lock(&part_parser_lock);
	list_del(&p->list);
	spin_unlock(&part_parser_lock);
	return 0;
}
EXPORT_SYMBOL_GPL(deregister_mtd_parser);

int parse_mtd_partitions(struct mtd_info *master, const char **types,
			 struct mtd_partition **pparts, unsigned long origin)
{
	struct mtd_part_parser *parser;
	int ret = 0;

	for ( ; ret <= 0 && *types; types++) {
		parser = get_partition_parser(*types);
		if (!parser && !request_module("%s", *types))
				parser = get_partition_parser(*types);
		if (!parser) {
			printk(KERN_NOTICE "%s partition parsing not available\n",
			       *types);
			continue;
		}
		ret = (*parser->parse_fn)(master, pparts, origin);
		if (ret > 0) {
			printk(KERN_NOTICE "%d %s partitions found on MTD device %s\n",
			       ret, parser->name, master->name);
		}
		put_partition_parser(parser);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(parse_mtd_partitions);
