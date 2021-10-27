/* Copyright 2021 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config_parser.h"

#include "util.h"

#define LIST_DEFAULT_SIZE (100)

struct config_entry_list *new_config_entry_list(void)
{
	/*
	 * There are <100 CLI options, configuration file will likely have
	 * a similar number of config entries.
	 */
	struct config_entry *entries =
	    calloc(LIST_DEFAULT_SIZE, sizeof(struct config_entry));
	if (!entries)
		return NULL;

	struct config_entry_list *list =
	    calloc(1, sizeof(struct config_entry_list));
	if (!list) {
		free(entries);
		return NULL;
	}
	list->entries = entries;
	list->num_allocated_ = LIST_DEFAULT_SIZE;
	list->num_entries = 0;
	return list;
}

void clear_config_entry(struct config_entry *entry)
{
	free((char *)entry->key);
	free((char *)entry->value);
}

void free_config_entry_list(struct config_entry_list *list)
{
	if (!list)
		return;
	for (size_t i = 0; i < list->num_entries; i++) {
		clear_config_entry(list->entries + i);
	}
	free(list->entries);
	free(list);
}

bool parse_config_line(const char *config_line, struct config_entry *entry)
{
	if (!entry)
		return false;
	/* Parsing will modify |config_line| in place, so make a copy. */
	char *line = strdup(config_line);
	if (!line)
		return false;
	char *value = line;

	/* After tokenize call, value will points to a substring after '='.
	 * If there is no '=' in the string, key will contain the entire string
	 * while value will be NULL.
	 */
	char *key = tokenize(&value, "=");
	key = strip(key);
	value = strip(value);
	if (!key || !value || key[0] == '\0' || value[0] == '\0') {
		warn("unable to parse %s", config_line);
		free(line);
		return false;
	}
	entry->key = strdup(key);
	entry->value = strdup(value);
	if (!entry->key || !entry->value) {
		clear_config_entry(entry);
		free(line);
		return false;
	}
	free(line);
	return true;
}

bool parse_config_file(FILE *config_file, struct config_entry_list *list)
{
	/* |list| must point to a valid entry list. */
	if (!list)
		return false;
	bool ret = true;
	char *line = NULL;
	size_t len = 0;
	bool is_first_line = true;
	while (getmultiline(&line, &len, config_file) != -1) {
		char *stripped_line = strip(line);
		/*
		 * The first line of the configuration file must match the
		 * special directive.
		 */
		if (is_first_line) {
			if (strcmp(line, "% minijail-config-file v0")) {
				ret = false;
				break;
			} else {
				is_first_line = false;
				continue;
			}
		}
		/*
		 * Skip blank lines and all comments. Comment lines start with
		 * '#'.
		 */
		if (stripped_line[0] == '\0' || stripped_line[0] == '#')
			continue;

		/*
		 * Check if the list is full, and reallocate with doubled
		 * capacity if so.
		 */
		if (list->num_entries >= list->num_allocated_) {
			list->entries = realloc(
			    list->entries, list->num_allocated_ * 2 *
					       sizeof(struct config_entry));
			if (list->entries == NULL) {
				ret = false;
				break;
			}
			list->num_allocated_ = list->num_allocated_ * 2;
		}

		struct config_entry *entry = list->entries + list->num_entries;
		if (!parse_config_line(stripped_line, entry)) {
			ret = false;
			goto free_line;
		}
		++list->num_entries;
	}
	/*
	 * getmultiline() behaves similarly with getline (3). It returns -1
	 * when read into EOF or the following errors.
	 */
	if (errno == EINVAL || errno == ENOMEM) {
		ret = false;
	}

	/* Shrink the list to save memory. */
	if (list->num_entries < list->num_allocated_) {
		list->entries =
		    realloc(list->entries,
			    list->num_entries * sizeof(struct config_entry));
		list->num_allocated_ = list->num_entries;
	}

free_line:
	free(line);
	return ret;
}
