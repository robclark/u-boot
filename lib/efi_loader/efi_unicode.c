/*
*  EFI Unicode interface
 *
 *  Copyright (c) 2017 Leif Lindholm
 *
 *  SPDX-License-Identifier:     GPL-2.0+
 */

#include <common.h>
#include <charset.h>
#include <linux/ctype.h>
#include <efi_loader.h>

const efi_guid_t efi_guid_unicode_collation_protocol =
	EFI_UNICODE_COLLATION_PROTOCOL_GUID;

const efi_guid_t efi_guid_unicode_collation_protocol2 =
	EFI_UNICODE_COLLATION_PROTOCOL2_GUID;

static int matchn(efi_string_t s1, unsigned n1, efi_string_t s2, unsigned n2)
{
	char u1[MAX_UTF8_PER_UTF16 * n1 + 1];
	char u2[MAX_UTF8_PER_UTF16 * n2 + 1];

	*utf16_to_utf8((u8 *)u1, s1, n1) = '\0';
	*utf16_to_utf8((u8 *)u2, s2, n2) = '\0';

	return strcasecmp(u1, u2);
}

static efi_intn_t EFIAPI stri_coll(struct efi_unicode_collation_protocol *this,
				   efi_string_t s1,
				   efi_string_t s2)
{
	EFI_ENTRY("%p, \"%ls\", \"%ls\"", this, s1, s2);

	unsigned n1 = utf16_strlen(s1);
	unsigned n2 = utf16_strlen(s2);

	return EFI_EXIT(matchn(s1, n1, s2, n2));
}

static bool match(efi_string_t string, efi_string_t pattern)
{
	while (true) {
		uint16_t p = *pattern++;
		bool matches = false;

		if (p == '\0' || *string == '\0') {
			/*
			 * End of pattern or string, succeed if
			 * end of both:
			 */
			return *string == p;
		}

		switch (p) {
		case '*':
			/* Match zero or more chars: */
			while (*string != '\0') {
				if (match(string, pattern))
					return true;
				string++;
			}
			return match(string, pattern);
		case '?':
			/* Match any one char: */
			string++;
			break;
		case '[':
			/* Match char set, either [abc] or [a-c]: */

			if (pattern[0] == '\0' || pattern[0] == ']') {
				/* invalid pattern */
				return false;
			}

			if (pattern[1] == '-') {
				uint16_t lo, hi, c;

				/* range: [a-c] */
				lo = pattern[0];
				hi = pattern[2];

				if (hi == '\0' || hi == ']' || pattern[3] != ']') {
					/* invalid pattern */
					return false;
				}

				c  = tolower(*string);
				lo = tolower(lo);
				hi = tolower(hi);

				if (lo <= c && c <= hi)
					matches = true;

				pattern += 4;
			} else {
				/* set: [abc] */
				while ((p = *pattern++) && p != ']')
					if (matchn(string, 1, &p, 1))
						matches = true;
			}

			if (!matches)
				return false;

			string++;
			break;
		default:
			if (matchn(string, 1, &p, 1))
				return false;
			string++;
			break;
		}
	}
}

static bool EFIAPI metai_match(struct efi_unicode_collation_protocol *this,
			       efi_string_t string,
			       efi_string_t pattern)
{
	EFI_ENTRY("%p, \"%ls\", \"%ls\"", this, string, pattern);
	return EFI_EXIT(match(string, pattern));
}

static void EFIAPI str_lwr(struct efi_unicode_collation_protocol *this,
			   efi_string_t string)
{
	EFI_ENTRY("%p, \"%ls\"", this, string);
	EFI_EXIT(EFI_SUCCESS);
	return;
}

static void EFIAPI str_upr(struct efi_unicode_collation_protocol *this,
			   efi_string_t string)
{
	EFI_ENTRY("%p, \"%ls\"", this, string);
	EFI_EXIT(EFI_SUCCESS);
	return;
}

static void EFIAPI fat_to_str(struct efi_unicode_collation_protocol *this,
			      efi_uintn_t fat_size,
			      uint8_t *fat,
			      efi_string_t string)
{
	EFI_ENTRY("%p, %zu, \"%s\", %p", this, fat_size, fat, string);
	EFI_EXIT(EFI_SUCCESS);
	return;
}

static bool EFIAPI str_to_fat(struct efi_unicode_collation_protocol *this,
			      efi_string_t string,
			      efi_uintn_t fat_size,
			      uint8_t *fat)
{
	EFI_ENTRY("%p, \"%ls\", %zu, %p", this, string, fat_size, fat);
	return EFI_EXIT(false);
}

const struct efi_unicode_collation_protocol efi_unicode_collation = {
	.stri_coll = stri_coll,
	.metai_match = metai_match,
	.str_lwr = str_lwr,
	.str_upr = str_upr,
	.fat_to_str = fat_to_str,
	.str_to_fat = str_to_fat,
	.supported_languages = (uint8_t *)"eng",
};
