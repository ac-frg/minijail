/* Copyright 2021 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config_parser.h"

#include "util.h"
/* clang-format off */
#define LIST_DEFAULT_SIZE (100)
/* clang-format on */
struct config_entry_list *new_config_entry_list(void)
{
	/*
	 * There are <100 CLI options, configuration file will likely have
	 * a similar number of config entries.
	 */
	struct config_entry *array =
	    calloc(LIST_DEFAULT_SIZE, sizeof(struct config_entry));
	if (!array) {
		return NULL;
	}

	struct config_entry_list *list =
	    calloc(1, sizeof(struct config_entry_list));
	if (!list) {
		free(array);
		return NULL;
	}
	list->array = array;
	list->size = LIST_DEFAULT_SIZE;
	list->used = 0;
	return list;
}

void clear_config_entry(struct config_entry *entry)
{
	if (entry->key) {
		free(entry->key);
	}
	if (entry->value) {
		free(entry->value);
	}
}

void free_config_entry_list(struct config_entry_list *list)
{
	if (!list)
		return;
	for (size_t i = 0; i < list->used; i++) {
		clear_config_entry(list->array + i);
	}
	free(list->array);
	free(list);
}

int parse_config_line(const char *config_line, struct config_entry *entry)
{
	if (!entry) {
		return -1;
	}
	/* Parsing will modify |config_line| in place, so make a copy. */
	char *line = strdup(config_line);
	if (!line)
		return -1;
	char *value = line;

	/* After tokenize call, value will points to a substring after '='.
	 * If there is no '=' in the string, key will contains the entire string
	 * while value will be NULL.
	 */
	char *key = tokenize(&value, "=");
	key = strip(key);
	value = strip(value);
	if (!key || !value || key[0] == '\0' || value[0] == '\0') {
		fprintf(stderr, "unable to parse %s\n", config_line);
		free(line);
		return -1;
	}
	entry->key = strdup(key);
	entry->value = strdup(value);
	if (!entry->key || !entry->value) {
		clear_config_entry(entry);
		free(line);
		return -1;
	}
	free(line);
	return 0;
}

int parse_config_file(FILE *config_file, struct config_entry_list *list)
{
	/* |list| must point to a valid entry list. */
	if (!list) {
		return -1;
	}
	int ret = 0;
	char *line = NULL;
	size_t len = 0;
	while (getmultiline(&line, &len, config_file) != -1) {
		char *value = line;
		value = strip(value);

		/*
		 * Skip blank lines and all comments. Comment lines start with
		 * '#'.
		 */
		if (value[0] == '\0' || value[0] == '#') {
			continue;
		}

		/* Check if the list is full, and reallocate if so. */
		if (list->used >= list->size) {
			/* Edge case: the list is not properly initialized. */
			if (list->size == 0) {
				list->size = LIST_DEFAULT_SIZE;
				list->used = 0;
			}
			list->array = realloc(list->array,
					      list->size * 2 *
						  sizeof(struct config_entry));
			if (list->array == NULL) {
				break;
			}
			list->size = list->size * 2;
		}

		struct config_entry *entry = list->array + list->used;
		ret = parse_config_line(line, entry);
		if (ret < 0) {
			goto free_line;
		}
		++list->used;
	}
	if (errno == EINVAL || errno == ENOMEM) {
		ret = -1;
	}

	/* Shrink the list to save memory. */
	if (list->used < list->size) {
		list->array = realloc(list->array,
				      list->used * sizeof(struct config_entry));
		list->size = list->used;
	}

free_line:
	free(line);
	return ret;
}