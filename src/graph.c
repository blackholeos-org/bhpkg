#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bhpkg.h"

void build_list_init(BuildList *list) {
    list->capacity = 16;
    list->count = 0;
    list->pkgs = xmalloc(list->capacity * sizeof(Package *));
}

void build_list_add(BuildList *list, Package *pkg) {
    if (list->count >= list->capacity) {
        list->capacity *= 2;
        list->pkgs = xrealloc(list->pkgs, list->capacity * sizeof(Package *));
    }
    list->pkgs[list->count++] = pkg;
}

void build_list_free(BuildList *list) {
    if (list->pkgs) free(list->pkgs);
    list->pkgs = NULL;
    list->count = 0;
    list->capacity = 0;
}

static bool check_version(const char *installed_ver, const char *constraint) {
    if (!constraint || strlen(constraint) == 0) return true;
    
    char op[3] = {0}; char target[64] = {0};
    if (sscanf(constraint, "%2[=><]%63s", op, target) != 2) return true;
    
    int cmp = strverscmp(installed_ver, target);
    if (strcmp(op, ">=") == 0) return cmp >= 0;
    if (strcmp(op, "<=") == 0) return cmp <= 0;
    if (strcmp(op, "==") == 0 || strcmp(op, "=") == 0) return cmp == 0;
    if (strcmp(op, ">") == 0) return cmp > 0;
    if (strcmp(op, "<") == 0) return cmp < 0;
    return true; 
}

int resolve_dependencies(Package *pkg, BuildList *build_order) {
    if (pkg->state == STATE_VISITING) {
        print_err("FATAL: Circular dependency detected involving '%s'", pkg->name);
        exit(1);
    }
    if (pkg->state == STATE_RESOLVED) return 0;

    pkg->state = STATE_VISITING;

    for (size_t i = 0; i < pkg->dep_count; i++) {
        Package *dep = pkg->deps[i];
        if (!dep) continue; //dependency not found in database skipped (will error in build phase if critical)
        
        if (!check_version(dep->version, pkg->dep_constraints[i])) {
            print_err("Constraint failed: %s needs %s%s (Found: %s)", 
                    pkg->name, dep->name, pkg->dep_constraints[i], dep->version);
            exit(1);
        }
        resolve_dependencies(dep, build_order);
    }

    pkg->state = STATE_RESOLVED;
    build_list_add(build_order, pkg);
    return 0;
}