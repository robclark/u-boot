/*
 *  EFI device path interface
 *
 *  Copyright (c) 2017 Leif Lindholm
 *
 *  SPDX-License-Identifier:     GPL-2.0+
 */

#include <common.h>
#include <efi_loader.h>

const efi_guid_t efi_guid_device_path_utilities_protocol =
		EFI_DEVICE_PATH_UTILITIES_PROTOCOL_GUID;

static UINTN get_device_path_size(const struct efi_device_path *device_path)
{
	EFI_ENTRY("%p", device_path);
	return EFI_EXIT(0);
}

static struct efi_device_path *duplicate_device_path(
	const struct efi_device_path *device_path)
{
	EFI_ENTRY("%p", device_path);
	return EFI_EXIT(NULL);
}

static struct efi_device_path *append_device_path(
	const struct efi_device_path *src1,
	const struct efi_device_path *src2)
{
	EFI_ENTRY("%p, %p", src1, src2);
	return EFI_EXIT(NULL);
}

static struct efi_device_path *append_device_node(
	const struct efi_device_path *device_path,
	const struct efi_device_path *device_node)
{
	EFI_ENTRY("%p, %p", device_path, device_node);
	return EFI_EXIT(NULL);
}

static struct efi_device_path *append_device_path_instance(
	const struct efi_device_path *device_path,
	const struct efi_device_path *device_path_instance)
{
	EFI_ENTRY("%p, %p", device_path, device_path_instance);
	return EFI_EXIT(NULL);
}

static struct efi_device_path *get_next_device_path_instance(
	struct efi_device_path **device_path_instance,
	UINTN *device_path_instance_size)
{
	EFI_ENTRY("%p, %p", device_path_instance, device_path_instance_size);
	return EFI_EXIT(NULL);
}

static struct efi_device_path *create_device_node(
	uint8_t node_type, uint8_t node_sub_type, uint16_t node_length)
{
	EFI_ENTRY("%u, %u, %u", node_type, node_sub_type, node_length);
	return EFI_EXIT(NULL);
}

static bool is_device_path_multi_instance(
	const struct efi_device_path *device_path)
{
	EFI_ENTRY("%p", device_path);
	return EFI_EXIT(false);
}

const struct efi_device_path_utilities_protocol efi_device_path_utilities = {
	.get_device_path_size = get_device_path_size,
	.duplicate_device_path = duplicate_device_path,
	.append_device_path = append_device_path,
	.append_device_node = append_device_node,
	.append_device_path_instance = append_device_path_instance,
	.get_next_device_path_instance = get_next_device_path_instance,
	.create_device_node = create_device_node,
	.is_device_path_multi_instance = is_device_path_multi_instance,
};
