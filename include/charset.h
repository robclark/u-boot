/*
 *  charset conversion utils
 *
 *  Copyright (c) 2017 Rob Clark
 *
 *  SPDX-License-Identifier:     GPL-2.0+
 */

#ifndef __CHARSET_H_
#define __CHARSET_H_

#define MAX_UTF8_PER_UTF16 4

size_t utf16_strlen(uint16_t *in);
size_t utf16_strnlen(const uint16_t *in, size_t count);
uint8_t *utf16_to_utf8(uint8_t *dest, const uint16_t *src, size_t size);

#endif /* __CHARSET_H_ */
