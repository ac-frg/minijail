/* Copyright 2021 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#ifdef __cplusplus
extern "C" {
#endif

struct config_entry {
	const char *key;
	const char *value;
	struct config_entry *next;
	struct config_entry *last;
	/*
	 * The size of the entry list, assuming the current entry
	 * is the header, always counts from the next entry.
	 */
	size_t list_len;
};

struct config_entry *new_config_entry(void);

/*
 * Free the list pointed to by |head|. |head| itself will not be freed.
 */
void free_config_entry_list(struct config_entry *head);

struct config_entry *parse_config_line(const char *config_line);
int parse_config_file(FILE *config_file, struct config_entry *head);

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* CONFIG_PARSER_H */
