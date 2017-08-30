/*
*  EFI Unicode interface
 *
 *  Copyright (c) 2017 Leif Lindholm
 *
 *  SPDX-License-Identifier:     GPL-2.0+
 */

#include <common.h>
#include <efi_loader.h>

const efi_guid_t efi_guid_unicode_collation_protocol2 =
	EFI_UNICODE_COLLATION_PROTOCOL2_GUID;

INTN stri_coll(struct efi_unicode_collation_protocol *this,
	       efi_string_t s1,
	       efi_string_t s2)
{
	EFI_ENTRY("%p, \"%ls\", \"%ls\"", this, s1, s2);
	return EFI_EXIT(0);
}

bool metai_match(struct efi_unicode_collation_protocol *this,
		 efi_string_t string,
		 efi_string_t pattern)
{
	EFI_ENTRY("%p, \"%ls\", \"%ls\"", this, string, pattern);
	return EFI_EXIT(false);
}

void str_lwr(struct efi_unicode_collation_protocol *this,
	     efi_string_t string)
{
	EFI_ENTRY("%p, \"%ls\"", this, string);
	EFI_EXIT(0);
	return;
}

void str_upr(struct efi_unicode_collation_protocol *this,
	     efi_string_t string)
{
	EFI_ENTRY("%p, \"%ls\"", this, string);
	EFI_EXIT(0);
	return;
}

void fat_to_str(struct efi_unicode_collation_protocol *this,
		UINTN fat_size,
		uint8_t *fat,
		efi_string_t string)
{
	EFI_ENTRY("%p, %lu, \"%s\", %p", this, fat_size, fat, string);
	EFI_EXIT(0);
	return;
}

bool str_to_fat(struct efi_unicode_collation_protocol *this,
		efi_string_t string,
		UINTN fat_size,
		uint8_t *fat)
{
	EFI_ENTRY("%p, \"%ls\", %lu, %p", this, string, fat_size, fat);
	return EFI_EXIT(false);
}

const struct efi_unicode_collation_protocol efi_unicode_collation = {
	.stri_coll = stri_coll,
	.metai_match = metai_match,
	.str_lwr = str_lwr,
	.str_upr = str_upr,
	.fat_to_str = fat_to_str,
	.str_to_fat = str_to_fat
};
