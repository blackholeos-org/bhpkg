#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "bhpkg.h"

typedef struct
{
  const char *name;
  const char *constraint;
} SatConstraint;

typedef struct
{
  SatConstraint req;
  Package **cands;
  size_t cand_count;
  size_t cand_idx;
  size_t old_assign_count;
} StackFrame;

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
  char *copy, *tok;

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

static int
compare_versions_desc (const void *a, const void *b)
{
  Package *pa = *(Package **)a;
  Package *pb = *(Package **)b;
  return bhpkg_vercmp (pb->version, pa->version);
}

/* Iterative DPLL Solver to completely prevent C stack overflow and solve scalable logic constraints */
static bool
iterative_sat_solve (Package ***assignment, size_t *assign_count, SatConstraint *initial_req)
{
  size_t stack_cap = 4096;
  StackFrame *stack = xmalloc (stack_cap * sizeof (StackFrame));
  size_t stack_top = 0;
  
  size_t queue_cap = 4096;
  SatConstraint *queue = xmalloc (queue_cap * sizeof (SatConstraint));
  size_t q_head = 0, q_tail = 0;
  
  size_t assign_cap = 4096;
  *assignment = xmalloc (assign_cap * sizeof (Package *));
  *assign_count = 0;

  queue[q_tail++] = *initial_req;

  while (true)
    {
      if (q_head == q_tail)
        {
          free (stack);
          free (queue);
          return true; /* All constraints satisfied */
        }
        
      SatConstraint req = queue[q_head++];
      Package *existing = find_in_assignment (*assignment, *assign_count, req.name);
      
      if (existing)
        {
          if (!check_version (existing->version, req.constraint))
            goto backtrack;
          continue; /* Constraint met */
        }

      /* Create a new branch (Choice Point) */
      if (stack_top >= stack_cap)
        {
          stack_cap *= 2;
          stack = xrealloc (stack, stack_cap * sizeof (StackFrame));
        }

      StackFrame *frame = &stack[stack_top++];
      frame->req = req;
      frame->cands = db_fetch_all_versions (req.name, &frame->cand_count);
      qsort (frame->cands, frame->cand_count, sizeof (Package *), compare_versions_desc);
      frame->cand_idx = 0;
      frame->old_assign_count = *assign_count;

explore_candidates:
      if (frame->cand_idx >= frame->cand_count)
        {
          free (frame->cands);
          stack_top--;
backtrack:
          if (stack_top == 0)
            {
              free (stack);
              free (queue);
              return false; /* Unsatisfiable */
            }
          frame = &stack[stack_top - 1];
          *assign_count = frame->old_assign_count;
          
          /* Re-evaluate queue position */
          q_tail = q_head; 
          for (size_t i = 0; i < *assign_count; i++)
            {
              Package *p = (*assignment)[i];
              for (size_t d = 0; d < p->dep_count; d++)
                {
                  queue[q_tail].name = p->dep_names[d];
                  queue[q_tail].constraint = p->dep_constraints[d];
                  q_tail++;
                }
              if (!p->is_installed && strcmp (p->type, "source") == 0)
                {
                  for (size_t d = 0; d < p->makedep_count; d++)
                    {
                      queue[q_tail].name = p->makedep_names[d];
                      queue[q_tail].constraint = p->makedep_constraints[d];
                      q_tail++;
                    }
                }
            }
          goto explore_candidates;
        }

      Package *cand = frame->cands[frame->cand_idx++];
      if (!check_version (cand->version, frame->req.constraint))
        goto explore_candidates;

      if (*assign_count >= assign_cap)
        {
          assign_cap *= 2;
          *assignment = xrealloc (*assignment, assign_cap * sizeof (Package *));
        }
      (*assignment)[(*assign_count)++] = cand;

      size_t needed = cand->dep_count + (!cand->is_installed && strcmp (cand->type, "source") == 0 ? cand->makedep_count : 0);
      if (q_tail + needed >= queue_cap)
        {
          queue_cap *= 2;
          queue = xrealloc (queue, queue_cap * sizeof (SatConstraint));
        }

      for (size_t d = 0; d < cand->dep_count; d++)
        {
          queue[q_tail].name = cand->dep_names[d];
          queue[q_tail].constraint = cand->dep_constraints[d];
          q_tail++;
        }
        
      if (!cand->is_installed && strcmp (cand->type, "source") == 0)
        {
          for (size_t d = 0; d < cand->makedep_count; d++)
            {
              queue[q_tail].name = cand->makedep_names[d];
              queue[q_tail].constraint = cand->makedep_constraints[d];
              q_tail++;
            }
        }
    }
}

static void
kahn_topological_sort (Package **assignment, size_t count, BuildList *order)
{
  int *in_degree = calloc (count, sizeof (int));
  int **adj = malloc (count * sizeof (int *));
  int *adj_count = calloc (count, sizeof (int));
  int *adj_cap = calloc (count, sizeof (int));
  
  for (size_t i = 0; i < count; i++)
    {
      adj_cap[i] = 4;
      adj[i] = malloc (adj_cap[i] * sizeof (int));
    }

  for (size_t i = 0; i < count; i++)
    {
      Package *p = assignment[i];
      for (size_t j = 0; j < count; j++)
        {
          Package *dep = assignment[j];
          if (i == j) continue;
          
          bool is_dep = false;
          for (size_t d = 0; d < p->dep_count; d++)
            if (strcmp (p->dep_names[d], dep->name) == 0) is_dep = true;
            
          if (!p->is_installed && strcmp (p->type, "source") == 0)
            {
              for (size_t d = 0; d < p->makedep_count; d++)
                if (strcmp (p->makedep_names[d], dep->name) == 0) is_dep = true;
            }
            
          if (is_dep)
            {
              if (adj_count[j] >= adj_cap[j])
                {
                  adj_cap[j] *= 2;
                  adj[j] = realloc (adj[j], adj_cap[j] * sizeof (int));
                }
              adj[j][adj_count[j]++] = i;
              in_degree[i]++;
            }
        }
    }

  int *queue = malloc (count * sizeof (int));
  int head = 0, tail = 0;

  for (size_t i = 0; i < count; i++)
    {
      if (in_degree[i] == 0)
        queue[tail++] = i;
    }

  while (head < tail)
    {
      int u = queue[head++];
      build_list_add (order, assignment[u]);
      
      for (int i = 0; i < adj_count[u]; i++)
        {
          int v = adj[u][i];
          if (--in_degree[v] == 0)
            queue[tail++] = v;
        }
    }

  free (queue);
  free (in_degree);
  free (adj_count);
  for (size_t i = 0; i < count; i++) free (adj[i]);
  free (adj);
  free (adj_cap);
}

int
resolve_dependencies (Package *root, BuildList *build_order)
{
  Package **assignment = NULL;
  size_t assign_count = 0;
  SatConstraint req = { root->name, "" };

  if (!iterative_sat_solve (&assignment, &assign_count, &req))
    {
      print_err ("Dependency resolution failed for '%s'. Unmet constraints or conflicts.", root->name);
      if (assignment) free (assignment);
      exit (EXIT_FAILURE);
    }

  kahn_topological_sort (assignment, assign_count, build_order);

  free (assignment);
  return 0;
}