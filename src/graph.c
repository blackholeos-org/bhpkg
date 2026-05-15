#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "bhpkg.h"

#define CONFLICT_HASH_SIZE 4096
static ConflictNode *g_conflict_cache[CONFLICT_HASH_SIZE] = { NULL };

typedef struct {
  const char *name;
  const char *constraint;
} SatConstraint;

void
build_list_init (BuildList *list)
{
  list->capacity = 16;
  list->count = 0;
  list->pkgs = xmalloc (list->capacity * sizeof (Package *));
}

void
build_list_add (BuildList *list, Package *pkg)
{
  if (list->count >= list->capacity)
    {
      list->capacity *= 2;
      list->pkgs = xrealloc (list->pkgs, list->capacity * sizeof (Package *));
    }
  list->pkgs[list->count++] = pkg;
}

void
build_list_free (BuildList *list)
{
  if (list->pkgs)
    free (list->pkgs);
  
  list->pkgs = NULL;
  list->count = 0;
  list->capacity = 0;
}

static bool
check_single_constraint (const char *installed_ver, const char *constraint)
{
  char op[3] = { 0 };
  char target[64] = { 0 };
  int cmp;

  if (sscanf (constraint, "%2[=><]%63s", op, target) != 2)
    return true;

  cmp = bhpkg_vercmp (installed_ver, target);
  
  if (strcmp (op, ">=") == 0) return cmp >= 0;
  if (strcmp (op, "<=") == 0) return cmp <= 0;
  if (strcmp (op, "==") == 0 || strcmp (op, "=") == 0) return cmp == 0;
  if (strcmp (op, ">") == 0)  return cmp > 0;
  if (strcmp (op, "<") == 0)  return cmp < 0;

  return true;
}

static bool
check_version (const char *installed_ver, const char *constraints)
{
  char *copy;
  char *tok;

  if (!constraints || strlen (constraints) == 0)
    return true;

  copy = xstrdup (constraints);
  tok = strtok (copy, ",|");

  while (tok)
    {
      if (!check_single_constraint (installed_ver, tok))
        {
          free (copy);
          return false;
        }
      tok = strtok (NULL, ",|");
    }

  free (copy);
  return true;
}

static Package *
find_in_assignment (Package **assignment, size_t count, const char *name)
{
  for (size_t i = 0; i < count; i++)
    {
      if (strcmp (assignment[i]->name, name) == 0)
        return assignment[i];
    }
  return NULL;
}

static inline uint32_t
hash_state (Package **assignment, size_t count, const char *target, const char *constraint)
{
  uint32_t hash = 2166136261u;
  for (size_t i = 0; i < count; i++)
    {
      const char *p = assignment[i]->name;
      while (*p) { hash ^= (uint8_t) *p++; hash *= 16777619u; }
      p = assignment[i]->version;
      while (*p) { hash ^= (uint8_t) *p++; hash *= 16777619u; }
    }
  const char *t = target;
  while (*t) { hash ^= (uint8_t) *t++; hash *= 16777619u; }
  const char *c = constraint;
  if (c)
    while (*c) { hash ^= (uint8_t) *c++; hash *= 16777619u; }
  return hash;
}

static bool
is_conflict_cached (uint32_t hash)
{
  uint32_t idx = hash % CONFLICT_HASH_SIZE;
  ConflictNode *curr = g_conflict_cache[idx];
  while (curr)
    {
      if (curr->state_hash == hash) return true;
      curr = curr->next;
    }
  return false;
}

static void
cache_conflict (uint32_t hash)
{
  uint32_t idx = hash % CONFLICT_HASH_SIZE;
  ConflictNode *node = xmalloc (sizeof (ConflictNode));
  node->state_hash = hash;
  node->next = g_conflict_cache[idx];
  g_conflict_cache[idx] = node;
}

static int
compare_versions_desc (const void *a, const void *b)
{
  Package *pa = *(Package **)a;
  Package *pb = *(Package **)b;
  return bhpkg_vercmp (pb->version, pa->version); /* Descending */
}

static bool
sat_solve (Package ***assignment, size_t *assign_count, size_t *assign_cap, 
           SatConstraint **queue, size_t q_head, size_t q_tail, size_t *q_cap)
{
  if (q_head == q_tail) return true;

  SatConstraint req = (*queue)[q_head];
  
  uint32_t state_hash = hash_state (*assignment, *assign_count, req.name, req.constraint);
  if (is_conflict_cached (state_hash))
    return false;

  Package *existing = find_in_assignment (*assignment, *assign_count, req.name);
  if (existing)
    {
      if (check_version (existing->version, req.constraint))
        {
          if (sat_solve (assignment, assign_count, assign_cap, queue, q_head + 1, q_tail, q_cap))
            return true;
        }
      cache_conflict (state_hash);
      return false;
    }

  size_t cand_count;
  Package **cands = db_fetch_all_versions (req.name, &cand_count);
  
  qsort (cands, cand_count, sizeof (Package *), compare_versions_desc);
  
  for (size_t i = 0; i < cand_count; i++)
    {
      if (check_version (cands[i]->version, req.constraint))
        {
          if (*assign_count >= *assign_cap)
            {
              *assign_cap *= 2;
              *assignment = xrealloc (*assignment, *assign_cap * sizeof (Package *));
            }
            
          (*assignment)[*assign_count] = cands[i];
          (*assign_count)++;

          size_t old_tail = q_tail;
          size_t needed = cands[i]->dep_count + (!cands[i]->is_installed && strcmp (cands[i]->type, "source") == 0 ? cands[i]->makedep_count : 0);
          
          if (q_tail + needed >= *q_cap)
            {
              while (q_tail + needed >= *q_cap) *q_cap *= 2;
              *queue = xrealloc (*queue, *q_cap * sizeof (SatConstraint));
            }
          
          for (size_t d = 0; d < cands[i]->dep_count; d++)
            {
              (*queue)[q_tail].name = cands[i]->dep_names[d];
              (*queue)[q_tail].constraint = cands[i]->dep_constraints[d];
              q_tail++;
            }
            
          if (!cands[i]->is_installed && strcmp (cands[i]->type, "source") == 0)
            {
              for (size_t d = 0; d < cands[i]->makedep_count; d++)
                {
                  (*queue)[q_tail].name = cands[i]->makedep_names[d];
                  (*queue)[q_tail].constraint = cands[i]->makedep_constraints[d];
                  q_tail++;
                }
            }

          if (sat_solve (assignment, assign_count, assign_cap, queue, q_head + 1, q_tail, q_cap))
            {
              free (cands);
              return true;
            }

          (*assign_count)--;
          q_tail = old_tail;
        }
    }
    
  if (cands) free (cands);
  cache_conflict (state_hash);
  return false;
}

static void
topo_visit (Package *p, Package **assignment, size_t assign_count, BuildList *order)
{
  if (p->state == STATE_RESOLVED) return;
  if (p->state == STATE_VISITING) return; 
  
  p->state = STATE_VISITING;
  
  for (size_t i = 0; i < p->dep_count; i++)
    {
      Package *dep = find_in_assignment (assignment, assign_count, p->dep_names[i]);
      if (dep) topo_visit (dep, assignment, assign_count, order);
    }
    
  if (!p->is_installed && strcmp (p->type, "source") == 0)
    {
      for (size_t i = 0; i < p->makedep_count; i++)
        {
          Package *dep = find_in_assignment (assignment, assign_count, p->makedep_names[i]);
          if (dep) topo_visit (dep, assignment, assign_count, order);
        }
    }
    
  p->state = STATE_RESOLVED;
  build_list_add (order, p);
}

int
resolve_dependencies (Package *root, BuildList *build_order)
{
  size_t assign_cap = 1024;
  Package **assignment = xmalloc (assign_cap * sizeof (Package *));
  size_t assign_count = 0;

  size_t q_cap = 4096;
  SatConstraint *queue = xmalloc (q_cap * sizeof (SatConstraint));
  
  queue[0].name = root->name;
  queue[0].constraint = "";
  
  if (!sat_solve (&assignment, &assign_count, &assign_cap, &queue, 0, 1, &q_cap))
    {
      print_err ("Dependency resolution failed for '%s'. Unmet constraints or conflicts.", root->name);
      free (assignment);
      free (queue);
      exit (EXIT_FAILURE);
    }

  for (size_t i = 0; i < assign_count; i++)
    assignment[i]->state = STATE_UNVISITED;

  Package *resolved_root = find_in_assignment (assignment, assign_count, root->name);
  topo_visit (resolved_root, assignment, assign_count, build_order);

  free (assignment);
  free (queue);
  return 0;
}