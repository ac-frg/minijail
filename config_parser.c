/* Copyright (c) 2021 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config_parser.h"

#include "util.h"

/* Insert the new entry after the head. */
static void insert_entry(struct config_entry* head,
		struct config_entry* entry) {
	if (!head || !entry) {
		return;
	}
	entry->next = head->next;
	if (head->next != NULL) {
		head->next->last = entry;
	}
	head->next = entry;
	entry->last = head;

	/* Update the list length. Counting from |head|'s next. */
	if (entry->next != NULL) {
		entry->list_len = entry->next->list_len + 1;
		head->list_len = entry->list_len + 1;
	} else {
		entry->list_len = 0;
		head->list_len = 1;
	}
}

struct config_entry *new_config_entry(void) {
	struct config_entry * entry = calloc(1, sizeof(struct config_entry));
	if (!entry) {
		die("could not allocate a config entry");
	}
	entry->last = entry->next = NULL;
	entry->key = entry->value = NULL;
	entry->list_len = 0;
	return entry;
}

void free_config_entry_list(struct config_entry * head) {
	while(head->next) {
		struct config_entry *current = head->next;
		head->next = current->next;
		free(current);
	}
	head->list_len = 0;
}

struct config_entry *parse_config_line(const char* config_line) {
	char *value = strdup(config_line);
	/* After tokenize call, value will points to a substring after '='.
	 * If there is no '=' in the string, key will contains the entire string
	 * while value will be NULL.
	 */
	char* key = tokenize(&value, "=");
	key = strip(key);
	value = strip(value);
	if (!key || !value || key[0] == '\0' || value[0] == '\0') {
		fprintf(stderr, "unable to parse %s\n", config_line);
		return NULL;
	}
	struct config_entry * entry = new_config_entry();
	entry->key = strdup(key);
	entry->value = strdup(value);
	if (!entry->key || !entry->value) {
		return NULL;
	}
	return entry;
}

int parse_config_file(FILE *config_file, struct config_entry *head) {
	/* |head| must point to a valid entry as a list header. */
	if (!head) {
		return -1;
	}
	int ret = 0;
	char *line = NULL;
	size_t len;
	while (getline(&line, &len, config_file) != -1) {
		char * value = line;
		value = strip(value);
		/* Skip blank lines and all comments. Comment lines start with '#'. */
		if (value[0] == '\0' || value[0] == '#') {
			continue;
		}
		struct config_entry * entry = parse_config_line(line);
		if (entry == NULL) {
			ret = -1;
			goto free_line;
		}
		insert_entry(head, entry);
	}
	if (errno == EINVAL || errno == ENOMEM) {
		free_config_entry_list(head);
		ret = -1;
	}

free_line:
	free(line);
  return ret;
}