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
	char *key;
	char *value;
};

struct config_entry_list {
	struct config_entry *array;
	size_t size;
	size_t used;
};

struct config_entry_list *new_config_entry_list(void);

void clear_config_entry(struct config_entry *entry);

void free_config_entry_list(struct config_entry_list *list);

int parse_config_line(const char *config_line, struct config_entry *entry);
int parse_config_file(FILE *config_file, struct config_entry_list *list);

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* CONFIG_PARSER_H */
