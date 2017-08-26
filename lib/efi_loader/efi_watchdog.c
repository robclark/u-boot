/*
 *  EFI device path interface
 *
 *  Copyright (c) 2017 Heinrich Schuchardt
 *
 *  SPDX-License-Identifier:     GPL-2.0+
 */

#include <common.h>
#include <efi_loader.h>

static struct efi_event *watchdog_timer_event;

static void EFIAPI efi_watchdog_timer_notify(struct efi_event *event,
					     void *context)
{
	EFI_ENTRY("%p, %p", event, context);

	printf("\nEFI: Watchdog timeout\n");
	EFI_CALL_VOID(efi_reset_system(EFI_RESET_COLD, EFI_SUCCESS, 0, NULL));

	EFI_EXIT(EFI_UNSUPPORTED);
}

efi_status_t efi_set_watchdog(unsigned long timeout)
{
	efi_status_t r;

	if (timeout)
		/* Reset watchdog */
		r = efi_set_timer(watchdog_timer_event, EFI_TIMER_RELATIVE,
				  10000000 * timeout);
	else
		/* Deactivate watchdog */
		r = efi_set_timer(watchdog_timer_event, EFI_TIMER_STOP, 0);
	return r;
}

/* This gets called from do_bootefi_exec(). */
int efi_watchdog_register(void)
{
	efi_status_t r;

	r = efi_create_event(EVT_TIMER | EVT_NOTIFY_SIGNAL, TPL_CALLBACK,
			     efi_watchdog_timer_notify, NULL,
			     &watchdog_timer_event);
	if (r != EFI_SUCCESS) {
		printf("ERROR: Failed to register watchdog event\n");
		return r;
	}
	/* Set watchdog to trigger after 5 minutes */
	r = efi_set_watchdog(300);
	if (r != EFI_SUCCESS) {
		printf("ERROR: Failed to set watchdog timer\n");
		return r;
	}
	return 0;
}
