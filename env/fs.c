/*
 *  Copyright (c) 2017 Rob Clark
 *
 *  SPDX-License-Identifier:     GPL-2.0+
 */

#include <common.h>

#include <command.h>
#include <environment.h>
#include <linux/stddef.h>
#include <malloc.h>
#include <memalign.h>
#include <search.h>
#include <errno.h>
#include <part.h>
#include <blk.h>
#include <usb.h>
#include <dm.h>
#include <fs.h>

#define ENV_FILE "uboot.env"

static char env_name[64] = "FILESYSTEM";
char *env_name_spec = env_name;

extern int usb_stor_curr_dev;

env_t *env_ptr;

static struct blk_desc *env_desc;
static int env_part;

DECLARE_GLOBAL_DATA_PTR;

static int env_fs_init(void)
{
	/* use default */
	gd->env_addr = (ulong)&default_environment[0];
	gd->env_valid = ENV_VALID;

	return 0;
}

#ifdef CONFIG_CMD_SAVEENV
static int env_fs_save(void)
{
	ALLOC_CACHE_ALIGN_BUFFER(env_t, env_new, sizeof(env_t));
	loff_t size;
	int err;

	if (!env_desc)
		return 1;

	err = env_export(env_new);
	if (err)
		return err;

	fs_set_blk_dev_with_part(env_desc, env_part);

	err = fs_write(ENV_FILE, (ulong)env_new, 0, sizeof(env_t), &size);
	if (err == -1) {
		printf("\n** Unable to write \"%s\" to %s **\n",
		       ENV_FILE, env_name_spec);
		return 1;
	}

	puts("done\n");
	return 0;
}
#endif /* CONFIG_CMD_SAVEENV */

void env_set_location(struct blk_desc *desc, int part)
{
	/* if we already have an environment location, keep it: */
	if (env_desc)
		return;

	snprintf(env_name, sizeof(env_name), "%s:%d",
		 desc->bdev->name, part);

	env_desc = desc;
	env_part = part;
}

static int env_find(void)
{
	struct udevice *dev;

#if defined(CONFIG_USB_STORAGE) && defined(CONFIG_DM_USB) && defined(CONFIG_CMD_USB)
	int err;

	err = usb_init();
	if (!err)
		usb_stor_curr_dev = usb_stor_scan(1);
#endif

	for (uclass_first_device_check(UCLASS_BLK, &dev);
	     dev;
	     uclass_next_device_check(&dev)) {
		struct blk_desc *desc = dev_get_uclass_platdata(dev);
		disk_partition_t info;
		int part = 1;

		printf("Scanning disk %s for environment...\n", dev->name);

		/* check all partitions: */
		while (!part_get_info(desc, part, &info)) {
			fs_set_blk_dev_with_part(desc, part);

			if (fs_exists(ENV_FILE)) {
				printf("Found %s on %s:%d\n", ENV_FILE,
				       dev->name, part);
				env_set_location(desc, part);
				return 0;
			}

			part++;
		}
	}

	return 1;
}

static int env_fs_load(void)
{
	ALLOC_CACHE_ALIGN_BUFFER(char, buf, CONFIG_ENV_SIZE);
	loff_t size;
	int err;

	if (env_find())
		goto err_env_relocate;

	fs_set_blk_dev_with_part(env_desc, env_part);

	err = fs_read(ENV_FILE, (ulong)buf, 0, CONFIG_ENV_SIZE, &size);
	if (err == -1) {
		printf("\n** Unable to read \"%s\" from %s **\n",
		       ENV_FILE, env_name_spec);
		goto err_env_relocate;
	}

	env_import(buf, 1);
	return 0;

err_env_relocate:
	set_default_env("!could not find environment");
	return 0;
}

U_BOOT_ENV_LOCATION(fs) = {
	.location	= ENVL_FS,
	ENV_NAME("FS")
	.init		= env_fs_init,
	.load_late	= env_fs_load,
#ifdef CONFIG_CMD_SAVEENV
	.save		= env_save_ptr(env_fs_save),
#endif
};
