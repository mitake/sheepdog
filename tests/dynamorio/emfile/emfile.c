/*
 * Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * journaling.c: DynamoRIO based fault injector for testing the journaling
 * mechanism of sheep
 */

#include "dr_api.h"

#include "../common.h"
#include <stdint.h>
#include <string.h>

#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

static int nr_consumed_fds;

DR_EXPORT void dr_init(client_id_t id)
{
	int i;
	const char *option;

	init_log_file();

	option = dr_get_options(id);
	fi_printf("the passed option to this client: %s\n", option);
	nr_consumed_fds = atoi(option);
	fi_printf("number of consumed file descriptors: %d\n", nr_consumed_fds);

	for (i = 0; i < nr_consumed_fds; i++) {
		int fd = open("/dev/null", O_RDONLY);
		if (fd < 0)
			die("opening /dev/null failed: %m");
	}
}
