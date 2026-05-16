#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "bhpkg.h"

extern void *arena_alloc (size_t size);
extern void arena_init (void);
extern void arena_free_all (void);

typedef int32_t Lit;
#define LIT_VAR(l) (abs(l))
#define LIT_SIGN(l) ((l) < 0)
#define MAKE_LIT(v, sign) ((sign) ? -(v) : (v))

typedef struct
{
  int size;
  Lit *lits;
} Clause;

typedef struct
{
  int *data;
  int size;
  int cap;
} LitVec;

typedef struct
{
  int assigns;    /* 0=unassigned, 1=true, -1=false */
  int level;
  Clause *reason;
  double activity;
} VarData;

typedef struct
{
  Package **pkgs;
  int count;
  int cap;
} PkgList;

static int g_num_vars = 0;
static VarData *g_vars = NULL;
static LitVec *g_watches = NULL;

static LitVec g_trail;
static LitVec g_trail_lim;
static int g_qhead = 0;

static Clause **g_clauses = NULL;
static int g_num_clauses = 0;
static int g_cap_clauses = 0;

static Package **g_pkg_map = NULL;

static inline int
lit_index (Lit l)
{
  return (LIT_VAR (l) << 1) | (LIT_SIGN (l) ? 1 : 0);
}

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

static void
vec_push (LitVec *v, int val)
{
  if (v->size == v->cap)
    {
      v->cap = v->cap == 0 ? 4 : v->cap * 2;
      int *new_data = arena_alloc (v->cap * sizeof (int));
      if (v->size > 0)
        memcpy (new_data, v->data, v->size * sizeof (int));
      v->data = new_data;
    }
  v->data[v->size++] = val;
}

static void
add_clause (Lit *lits, int size)
{
  if (size == 0) return;

  Clause *c = arena_alloc (sizeof (Clause));
  c->size = size;
  c->lits = arena_alloc (size * sizeof (Lit));
  memcpy (c->lits, lits, size * sizeof (Lit));

  if (g_num_clauses >= g_cap_clauses)
    {
      g_cap_clauses = g_cap_clauses == 0 ? 1024 : g_cap_clauses * 2;
      Clause **new_clauses = arena_alloc (g_cap_clauses * sizeof (Clause *));
      if (g_num_clauses > 0)
        memcpy (new_clauses, g_clauses, g_num_clauses * sizeof (Clause *));
      g_clauses = new_clauses;
    }
  g_clauses[g_num_clauses] = c;

  if (size >= 2)
    {
      vec_push (&g_watches[lit_index (lits[0])], g_num_clauses);
      vec_push (&g_watches[lit_index (lits[1])], g_num_clauses);
    }
  else if (size == 1)
    {
      vec_push (&g_watches[lit_index (lits[0])], g_num_clauses);
    }
  g_num_clauses++;
}

static int
val (Lit l)
{
  int v = LIT_VAR (l);
  int asgn = g_vars[v].assigns;
  if (asgn == 0) return 0;
  return (asgn == 1) ^ LIT_SIGN (l) ? 1 : -1;
}

static void
unchecked_enqueue (Lit p, Clause *from)
{
  int v = LIT_VAR (p);
  g_vars[v].assigns = LIT_SIGN (p) ? -1 : 1;
  g_vars[v].level = g_trail_lim.size;
  g_vars[v].reason = from;
  vec_push (&g_trail, p);
}

static Clause *
bcp (void)
{
  while (g_qhead < g_trail.size)
    {
      Lit p = g_trail.data[g_qhead++];
      Lit false_lit = MAKE_LIT (LIT_VAR (p), !LIT_SIGN (p));
      LitVec *ws = &g_watches[lit_index (false_lit)];
      
      int i, j;
      for (i = 0, j = 0; i < ws->size; i++)
        {
          Clause *c = g_clauses[ws->data[i]];
          
          if (c->size == 1)
            {
              ws->data[j++] = ws->data[i];
              if (val (c->lits[0]) == -1)
                {
                  for (int k = i + 1; k < ws->size; k++)
                    ws->data[j++] = ws->data[k];
                  ws->size = j;
                  return c;
                }
              continue;
            }

          if (c->lits[0] == false_lit)
            {
              c->lits[0] = c->lits[1];
              c->lits[1] = false_lit;
            }

          if (val (c->lits[0]) == 1)
            {
              ws->data[j++] = ws->data[i];
              continue;
            }

          bool found_new_watch = false;
          for (int k = 2; k < c->size; k++)
            {
              if (val (c->lits[k]) != -1)
                {
                  c->lits[1] = c->lits[k];
                  c->lits[k] = false_lit;
                  vec_push (&g_watches[lit_index (c->lits[1])], ws->data[i]);
                  found_new_watch = true;
                  break;
                }
            }

          if (!found_new_watch)
            {
              ws->data[j++] = ws->data[i];
              if (val (c->lits[0]) == -1)
                {
                  for (int k = i + 1; k < ws->size; k++)
                    ws->data[j++] = ws->data[k];
                  ws->size = j;
                  
                  for (int ac = 0; ac < c->size; ac++)
                    g_vars[LIT_VAR (c->lits[ac])].activity += 1.0;
                    
                  return c;
                }
              else
                {
                  unchecked_enqueue (c->lits[0], c);
                }
            }
        }
      ws->size = j;
    }
  return NULL;
}

static void
cancel_until (int level)
{
  if (g_trail_lim.size > level)
    {
      for (int c = g_trail.size - 1; c >= g_trail_lim.data[level]; c--)
        {
          int v = LIT_VAR (g_trail.data[c]);
          g_vars[v].assigns = 0;
          g_vars[v].reason = NULL;
        }
      g_trail.size = g_trail_lim.data[level];
      g_trail_lim.size = level;
      g_qhead = g_trail.size;
    }
}

static bool
solve_cdcl (void)
{
  g_trail.size = 0;
  g_trail_lim.size = 0;
  g_qhead = 0;

  while (true)
    {
      Clause *confl = bcp ();
      if (confl != NULL)
        {
          if (g_trail_lim.size == 0)
            return false;

          int backtrack_level = g_trail_lim.size - 1;
          cancel_until (backtrack_level);
          
          Lit last_dec = g_trail.data[g_trail.size];
          unchecked_enqueue (MAKE_LIT (LIT_VAR (last_dec), !LIT_SIGN (last_dec)), NULL);
        }
      else
        {
          int next_var = 0;
          double max_act = -1;
          for (int i = 1; i <= g_num_vars; i++)
            {
              if (g_vars[i].assigns == 0 && g_vars[i].activity > max_act)
                {
                  max_act = g_vars[i].activity;
                  next_var = i;
                }
            }

          if (next_var == 0)
            return true;

          vec_push (&g_trail_lim, g_trail.size);
          unchecked_enqueue (MAKE_LIT (next_var, 0), NULL);
        }
    }
}

static void
kahn_topological_sort (Package **assignment, size_t count, BuildList *order)
{
  int *in_degree = calloc (count, sizeof (int));
  int **adj = xmalloc (count * sizeof (int *));
  int *adj_count = calloc (count, sizeof (int));
  int *adj_cap = calloc (count, sizeof (int));

  for (size_t i = 0; i < count; i++)
    {
      adj_cap[i] = 4;
      adj[i] = xmalloc (adj_cap[i] * sizeof (int));
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
                  adj[j] = xrealloc (adj[j], adj_cap[j] * sizeof (int));
                }
              adj[j][adj_count[j]++] = i;
              in_degree[i]++;
            }
        }
    }

  int *queue = xmalloc (count * sizeof (int));
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

static bool
eval_constraint (const char *ver, const char *constraint)
{
  if (!constraint || !*constraint)
    return true;

  const char *op = constraint;
  const char *val = constraint;
  while (*val == '<' || *val == '>' || *val == '=')
    val++;

  int cmp = bhpkg_vercmp (ver, val);

  if (strncmp (op, ">=", 2) == 0) return cmp >= 0;
  if (strncmp (op, "<=", 2) == 0) return cmp <= 0;
  if (strncmp (op, "==", 2) == 0 || strncmp (op, "=", 1) == 0) return cmp == 0;
  if (strncmp (op, ">", 1) == 0) return cmp > 0;
  if (strncmp (op, "<", 1) == 0) return cmp < 0;

  return true;
}

int
resolve_dependencies (Package *root, BuildList *build_order)
{
  arena_init ();

  PkgList u;
  u.count = 0;
  u.cap = 64;
  u.pkgs = xmalloc (u.cap * sizeof (Package *));

  u.pkgs[u.count++] = root;

  int qhead = 0;
  while (qhead < u.count)
    {
      Package *p = u.pkgs[qhead++];
      
      char **names[] = { p->dep_names, p->makedep_names };
      size_t counts[] = { p->dep_count, p->makedep_count };
      
      for (int t = 0; t < 2; t++)
        {
          if (t == 1 && (p->is_installed || strcmp (p->type, "source") != 0))
            continue;
              
          for (size_t i = 0; i < counts[t]; i++)
            {
              size_t cand_c;
              Package **cands = db_fetch_all_versions (names[t][i], &cand_c);
              for (size_t j = 0; j < cand_c; j++)
                {
                  bool found = false;
                  for (int k = 0; k < u.count; k++)
                    {
                      if (u.pkgs[k] == cands[j])
                        {
                          found = true;
                          break;
                        }
                    }
                  if (!found)
                    {
                      if (u.count == u.cap)
                        {
                          u.cap *= 2;
                          u.pkgs = xrealloc (u.pkgs, u.cap * sizeof (Package *));
                        }
                      u.pkgs[u.count++] = cands[j];
                    }
                }
              free (cands);
              
              cands = db_fetch_providers (names[t][i], &cand_c);
              for (size_t j = 0; j < cand_c; j++)
                {
                  bool found = false;
                  for (int k = 0; k < u.count; k++)
                    {
                      if (u.pkgs[k] == cands[j])
                        {
                          found = true;
                          break;
                        }
                    }
                  if (!found)
                    {
                      if (u.count == u.cap)
                        {
                          u.cap *= 2;
                          u.pkgs = xrealloc (u.pkgs, u.cap * sizeof (Package *));
                        }
                      u.pkgs[u.count++] = cands[j];
                    }
                }
              free (cands);
            }
        }
    }

  g_num_vars = u.count;
  g_vars = arena_alloc ((g_num_vars + 1) * sizeof (VarData));
  g_watches = arena_alloc (((g_num_vars + 1) * 2) * sizeof (LitVec));
  g_pkg_map = arena_alloc ((g_num_vars + 1) * sizeof (Package *));

  for (int i = 0; i <= g_num_vars; i++)
    {
      g_vars[i].assigns = 0;
      g_vars[i].activity = 1.0;
      g_pkg_map[i] = NULL;
    }
    
  for (int i = 0; i < ((g_num_vars + 1) * 2); i++)
    {
      g_watches[i].size = 0;
      g_watches[i].cap = 0;
      g_watches[i].data = NULL;
    }

  for (int i = 0; i < u.count; i++)
    {
      g_pkg_map[i + 1] = u.pkgs[i];
    }

  g_trail.size = 0; g_trail.cap = 0; g_trail.data = NULL;
  g_trail_lim.size = 0; g_trail_lim.cap = 0; g_trail_lim.data = NULL;
  g_num_clauses = 0; g_cap_clauses = 0; g_clauses = NULL;

  Lit root_clause[1] = { MAKE_LIT (1, 0) };
  add_clause (root_clause, 1);

  for (int i = 1; i <= g_num_vars; i++)
    {
      Package *p = g_pkg_map[i];
      char **names[] = { p->dep_names, p->makedep_names };
      char **constraints[] = { p->dep_constraints, p->makedep_constraints };
      size_t counts[] = { p->dep_count, p->makedep_count };
      
      for (int t = 0; t < 2; t++)
        {
          if (t == 1 && (p->is_installed || strcmp (p->type, "source") != 0))
            continue;
              
          for (size_t j = 0; j < counts[t]; j++)
            {
              Lit *clause = arena_alloc ((g_num_vars + 1) * sizeof (Lit));
              int c_size = 0;
              clause[c_size++] = MAKE_LIT (i, 1);
              
              for (int k = 1; k <= g_num_vars; k++)
                {
                  Package *cand = g_pkg_map[k];
                  bool match = false;
                  if (strcmp (cand->name, names[t][j]) == 0)
                    {
                      match = eval_constraint (cand->version, constraints[t][j]);
                    }
                  else
                    {
                      for (size_t pidx = 0; pidx < cand->provides_count; pidx++)
                        {
                          if (strcmp (cand->provides[pidx], names[t][j]) == 0)
                            {
                              match = true;
                              break;
                            }
                        }
                    }
                  if (match)
                    {
                      clause[c_size++] = MAKE_LIT (k, 0);
                    }
                }
              
              add_clause (clause, c_size);
            }
        }

      for (size_t j = 0; j < p->conflicts_count; j++)
        {
          for (int k = 1; k <= g_num_vars; k++)
            {
              if (i == k) continue;
              Package *cand = g_pkg_map[k];
              bool conflict = false;
              
              if (strcmp (cand->name, p->conflicts[j]) == 0)
                conflict = true;
              else
                {
                  for (size_t pidx = 0; pidx < cand->provides_count; pidx++)
                    {
                      if (strcmp (cand->provides[pidx], p->conflicts[j]) == 0)
                        {
                          conflict = true;
                          break;
                        }
                    }
                }
              
              if (conflict)
                {
                  Lit clause[2] = { MAKE_LIT (i, 1), MAKE_LIT (k, 1) };
                  add_clause (clause, 2);
                }
            }
        }
    }

  print_msg ("Solving dependency graph...");

  if (!solve_cdcl ())
    {
      print_err ("Dependency resolution failed. Conflicting or missing constraints.");
      arena_free_all ();
      free (u.pkgs);
      return -1;
    }

  Package **assignment = xmalloc (g_num_vars * sizeof (Package *));
  size_t assign_count = 0;

  for (int i = 1; i <= g_num_vars; i++)
    {
      if (g_vars[i].assigns == 1 && g_pkg_map[i])
        assignment[assign_count++] = g_pkg_map[i];
    }

  kahn_topological_sort (assignment, assign_count, build_order);

  for (size_t i = 0; i < assign_count; i++)
    {
      for (size_t j = 0; j < assignment[i]->obsoletes_count; j++)
        {
          print_warn ("'%s' obsoletes '%s'. Marking '%s' for automatic removal.",
                      assignment[i]->name, assignment[i]->obsoletes[j], assignment[i]->obsoletes[j]);
          db_remove_package (assignment[i]->obsoletes[j]);
        }
    }

  free (assignment);
  arena_free_all ();
  free (u.pkgs);
  return 0;
}