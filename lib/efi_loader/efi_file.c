/*
 *  EFI utils
 *
 *  Copyright (c) 2017 Rob Clark
 *
 *  SPDX-License-Identifier:     GPL-2.0+
 */

#include <common.h>
#include <charset.h>
#include <efi_loader.h>
#include <malloc.h>
#include <fs.h>

struct file_system {
	struct efi_simple_file_system_protocol base;
	struct efi_device_path *dp;
	struct blk_desc *desc;
	int part;
};
#define to_fs(x) container_of(x, struct file_system, base)

struct file_handle {
	struct efi_file_handle base;
	struct file_system *fs;
	loff_t offset;       /* current file position/cursor */
	int isdir;
	char path[0];
};
#define to_fh(x) container_of(x, struct file_handle, base)

static const struct efi_file_handle efi_file_handle_protocol;

static char *basename(struct file_handle *fh)
{
	char *s = strrchr(fh->path, '/');
	if (s)
		return s + 1;
	return fh->path;
}

static int set_blk_dev(struct file_handle *fh)
{
	return fs_set_blk_dev2(fh->fs->desc, fh->fs->part);
}

static int is_dir(struct file_handle *fh, const char *filename)
{
	char buf[256];
	struct fs_dirent d;
	const char *path;
	int ret;

	if (!filename) {
		path = fh->path;
	} else {
		ret = snprintf(buf, sizeof(buf), "%s/%s",
				fh->path, filename);
		if (ret >= sizeof(buf))
			return 0;
		path = buf;
	}

	set_blk_dev(fh);
	ret = fs_readdir(path, 0, &d);
	if (ret == -ENOTDIR) {
		return 0;
	} else if (ret == -ENXIO) {
		debug("WARNING: cannot read directories!\n");
		/*
		 * We don't know, assume regular file, but if
		 * the EFI app tries to read a directory, it
		 * won't work properly.  This will be a problem
		 * for fallback.efi as it searches /EFI/ for
		 * OS installations.  Too bad.
		 */
		return 0;
	} else {
		return 1;
	}
}

/* NOTE: despite what you would expect, 'file_name' is actually a path.
 * With windoze style backlashes, ofc.
 */
static struct efi_file_handle *file_open(struct file_system *fs,
		struct file_handle *parent, s16 *file_name)
{
	struct file_handle *fh;
	char f0[MAX_UTF8_PER_UTF16] = {0};
	int plen = 0;
	int flen = 0;

	if (file_name)
		utf16_to_utf8((u8 *)f0, (u16 *)file_name, 1);

	/* we could have a parent, but also an absolute path: */
	if (f0[0] == '\\') {
		plen = 0;
		flen = utf16_strlen((u16 *)file_name);
	} else if (parent) {
		plen = strlen(parent->path) + 1;
		flen = utf16_strlen((u16 *)file_name);
	}

	/* +2 is for null and '/' */
	fh = calloc(1, sizeof(*fh) + plen + (flen * MAX_UTF8_PER_UTF16) + 2);

	fh->base = efi_file_handle_protocol;
	fh->fs = fs;

	if (parent) {
		char *p = fh->path;

		if (plen > 0) {
			strcpy(p, parent->path);
			p += plen - 1;
			*p++ = '/';
		}

		utf16_to_utf8((u8 *)p, (u16 *)file_name, flen);

		/* sanitize path: */
		while ((p = strchr(p, '\\')))
			*p++ = '/';

		/* check if file exists: */
		if (set_blk_dev(fh))
			goto error;
		if (!fs_exists(fh->path))
			goto error;

		/* figure out if file is a directory: */
		fh->isdir = is_dir(fh, NULL);
	} else {
		fh->isdir = 1;
		strcpy(fh->path, "");
	}

	return &fh->base;

error:
	free(fh);
	return NULL;
}

static efi_status_t EFIAPI efi_file_open(struct efi_file_handle *file,
		struct efi_file_handle **new_handle,
		s16 *file_name, u64 open_mode, u64 attributes)
{
	struct file_handle *fh = to_fh(file);

	EFI_ENTRY("%p, %p, %p, %llu, %llu", file, new_handle, file_name,
		open_mode, attributes);

	*new_handle = file_open(fh->fs, fh, file_name);
	if (!*new_handle)
		return EFI_EXIT(EFI_NOT_FOUND);

	return EFI_EXIT(EFI_SUCCESS);
}

static efi_status_t EFIAPI efi_file_close(struct efi_file_handle *file)
{
	struct file_handle *fh = to_fh(file);
	EFI_ENTRY("%p", file);
	free(fh);
	return EFI_EXIT(EFI_SUCCESS);
}

static efi_status_t EFIAPI efi_file_delete(struct efi_file_handle *file)
{
	efi_file_close(file);
	return EFI_WARN_DELETE_FAILURE;
}

static efi_status_t file_read(struct file_handle *fh, u64 *buffer_size,
		void *buffer)
{
	loff_t actread;

	if (fs_read(fh->path, (ulong)buffer, fh->offset,
			*buffer_size, &actread))
		return EFI_DEVICE_ERROR;

	*buffer_size = actread;
	fh->offset += actread;

	return EFI_SUCCESS;
}

static efi_status_t dir_read(struct file_handle *fh, u64 *buffer_size,
		void *buffer)
{
	struct efi_file_info *info = buffer;
	struct fs_dirent dent;
	unsigned required_size;
	int ret;

	ret = fs_readdir(fh->path, fh->offset, &dent);

	if (ret == -ENOENT) {
		/* no more files in directory: */
		/* workaround shim.efi bug/quirk.. as find_boot_csv()
		 * loops through directory contents, it initially calls
		 * read w/ zero length buffer to find out how much mem
		 * to allocate for the EFI_FILE_INFO, then allocates,
		 * and then calls a 2nd time.  If we return size of
		 * zero the first time, it happily passes that to
		 * AllocateZeroPool(), and when that returns NULL it
		 * thinks it is EFI_OUT_OF_RESOURCES.  So on first
		 * call return a non-zero size:
		 */
		if (*buffer_size == 0)
			*buffer_size = sizeof(*info);
		else
			*buffer_size = 0;
		return EFI_SUCCESS;
	} else if (ret) {
		return EFI_DEVICE_ERROR;
	}

	/* check buffer size: */
	required_size = sizeof(*info) + 2 * (strlen(dent.name) + 1);
	if (*buffer_size < required_size) {
		*buffer_size = required_size;
		return EFI_BUFFER_TOO_SMALL;
	}

	*buffer_size = required_size;
	memset(info, 0, required_size);

	info->size = required_size;
	info->file_size = dent.size;
	info->physical_size = dent.size;

	if (is_dir(fh, dent.name))
		info->attribute |= EFI_FILE_DIRECTORY;

	ascii2unicode((u16 *)info->file_name, dent.name);

	fh->offset++;

	return EFI_SUCCESS;
}

static efi_status_t EFIAPI efi_file_read(struct efi_file_handle *file,
		u64 *buffer_size, void *buffer)
{
	struct file_handle *fh = to_fh(file);
	efi_status_t ret = EFI_SUCCESS;

	EFI_ENTRY("%p, %p, %p", file, buffer_size, buffer);

	if (set_blk_dev(fh)) {
		ret = EFI_DEVICE_ERROR;
		goto error;
	}

	if (fh->isdir) {
		ret = dir_read(fh, buffer_size, buffer);
	} else {
		ret = file_read(fh, buffer_size, buffer);
	}

error:
	return EFI_EXIT(ret);
}

static efi_status_t EFIAPI efi_file_write(struct efi_file_handle *file,
		u64 *buffer_size, void *buffer)
{
	EFI_ENTRY("%p, %p, %p", file, buffer_size, buffer);
	return EFI_EXIT(EFI_WRITE_PROTECTED);
}

static efi_status_t EFIAPI efi_file_getpos(struct efi_file_handle *file,
		u64 *pos)
{
	struct file_handle *fh = to_fh(file);
	EFI_ENTRY("%p, %p", file, pos);
	*pos = fh->offset;
	return EFI_EXIT(EFI_SUCCESS);
}

static efi_status_t EFIAPI efi_file_setpos(struct efi_file_handle *file,
		u64 pos)
{
	struct file_handle *fh = to_fh(file);
	efi_status_t ret = EFI_SUCCESS;

	EFI_ENTRY("%p, %llu", file, pos);

	if (fh->isdir && (pos != 0)) {
		ret = EFI_UNSUPPORTED;
		goto error;
	}

	if (pos == ~0ULL) {
		loff_t file_size;

		if (set_blk_dev(fh)) {
			ret = EFI_DEVICE_ERROR;
			goto error;
		}

		if (fs_size(fh->path, &file_size)) {
			ret = EFI_DEVICE_ERROR;
			goto error;
		}

		pos = file_size;
	}

	fh->offset = pos;

error:
	return EFI_EXIT(ret);
}

static efi_status_t EFIAPI efi_file_getinfo(struct efi_file_handle *file,
		efi_guid_t *info_type, u64 *buffer_size, void *buffer)
{
	struct file_handle *fh = to_fh(file);
	efi_status_t ret = EFI_SUCCESS;

	EFI_ENTRY("%p, %p, %p, %p", file, info_type, buffer_size, buffer);

	if (!guidcmp(info_type, &efi_file_info_guid)) {
		struct efi_file_info *info = buffer;
		char *filename = basename(fh);
		unsigned required_size;
		loff_t file_size;

		/* check buffer size: */
		required_size = sizeof(*info) + 2 * (strlen(filename) + 1);
		if (*buffer_size < required_size) {
			*buffer_size = required_size;
			ret = EFI_BUFFER_TOO_SMALL;
			goto error;
		}

		if (set_blk_dev(fh)) {
			ret = EFI_DEVICE_ERROR;
			goto error;
		}

		if (fs_size(fh->path, &file_size)) {
			ret = EFI_DEVICE_ERROR;
			goto error;
		}

		memset(info, 0, required_size);

		info->size = required_size;
		info->file_size = file_size;
		info->physical_size = file_size;

		if (fh->isdir)
			info->attribute |= EFI_FILE_DIRECTORY;

		ascii2unicode((u16 *)info->file_name, filename);
	} else {
		ret = EFI_UNSUPPORTED;
	}

error:
	return EFI_EXIT(ret);
}

static efi_status_t EFIAPI efi_file_setinfo(struct efi_file_handle *file,
		efi_guid_t *info_type, u64 buffer_size, void *buffer)
{
	EFI_ENTRY("%p, %p, %llu, %p", file, info_type, buffer_size, buffer);
	return EFI_EXIT(EFI_UNSUPPORTED);
}

static efi_status_t EFIAPI efi_file_flush(struct efi_file_handle *file)
{
	EFI_ENTRY("%p", file);
	return EFI_EXIT(EFI_SUCCESS);
}

static const struct efi_file_handle efi_file_handle_protocol = {
	.rev = EFI_FILE_PROTOCOL_REVISION,
	.open = efi_file_open,
	.close = efi_file_close,
	.delete = efi_file_delete,
	.read = efi_file_read,
	.write = efi_file_write,
	.getpos = efi_file_getpos,
	.setpos = efi_file_setpos,
	.getinfo = efi_file_getinfo,
	.setinfo = efi_file_setinfo,
	.flush = efi_file_flush,
};

struct efi_file_handle *efi_file_from_path(struct efi_device_path *fp)
{
	struct efi_simple_file_system_protocol *v;
	struct efi_file_handle *f;
	efi_status_t ret;

	v = efi_fs_from_path(fp);
	if (!v)
		return NULL;

	EFI_CALL(ret = v->open_volume(v, &f));
	if (ret != EFI_SUCCESS)
		return NULL;

	/* skip over device-path nodes before the file path: */
	while (fp && !EFI_DP_TYPE(fp, MEDIA_DEVICE, FILE_PATH)) {
		fp = efi_dp_next(fp);
	}

	while (fp) {
		struct efi_device_path_file_path *fdp =
			container_of(fp, struct efi_device_path_file_path, dp);
		struct efi_file_handle *f2;

		if (!EFI_DP_TYPE(fp, MEDIA_DEVICE, FILE_PATH)) {
			printf("bad file path!\n");
			f->close(f);
			return NULL;
		}

		EFI_CALL(ret = f->open(f, &f2, (s16 *)fdp->str, EFI_FILE_MODE_READ, 0));
		if (ret != EFI_SUCCESS)
			return NULL;

		fp = efi_dp_next(fp);

		EFI_CALL(f->close(f));
		f = f2;
	}

	return f;
}

static efi_status_t EFIAPI
efi_open_volume(struct efi_simple_file_system_protocol *this,
		struct efi_file_handle **root)
{
	struct file_system *fs = to_fs(this);

	EFI_ENTRY("%p, %p", this, root);

	*root = file_open(fs, NULL, NULL);

	return EFI_EXIT(EFI_SUCCESS);
}

struct efi_simple_file_system_protocol *
efi_simple_file_system(struct blk_desc *desc, int part,
		       struct efi_device_path *dp)
{
	struct file_system *fs;

	fs = calloc(1, sizeof(*fs));
	fs->base.rev = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_REVISION;
	fs->base.open_volume = efi_open_volume;
	fs->desc = desc;
	fs->part = part;
	fs->dp = dp;

	return &fs->base;
}
