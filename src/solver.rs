use crate::error::{AppError, Result};
use crate::types::{AppContext, PackageRef};
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};

const ACTIVITY_SCALE: u64 = 1_000_000;

fn order(c: char) -> i32 {
    if c.is_ascii_digit() {
        0
    } else if c.is_ascii_alphabetic() {
        c as i32
    } else if c == '~' {
        -1
    } else if c != '\0' {
        c as i32 + 256
    } else {
        0
    }
}

fn cmp_string(v_str: &str, r_str: &str) -> i32 {
    let mut v_chars = v_str.chars().peekable();
    let mut r_chars = r_str.chars().peekable();

    loop {
        let vc_peek = v_chars.peek().copied();
        let rc_peek = r_chars.peek().copied();

        if vc_peek.is_none() && rc_peek.is_none() {
            break;
        }

        let v_is_digit = vc_peek.map_or(false, |c| c.is_ascii_digit());
        let r_is_digit = rc_peek.map_or(false, |c| c.is_ascii_digit());

        if (!v_is_digit && vc_peek.is_some()) || (!r_is_digit && rc_peek.is_some()) {
            let vo = order(vc_peek.unwrap_or('\0'));
            let ro = order(rc_peek.unwrap_or('\0'));
            if vo != ro {
                return vo - ro;
            }
            if vc_peek.is_some() {
                v_chars.next();
            }
            if rc_peek.is_some() {
                r_chars.next();
            }
        } else {
            let mut vn: i64 = 0;
            let mut rn: i64 = 0;
            while let Some(&c) = v_chars.peek() {
                if !c.is_ascii_digit() {
                    break;
                }
                vn = vn
                    .saturating_mul(10)
                    .saturating_add((c as i64) - ('0' as i64));
                v_chars.next();
            }
            while let Some(&c) = r_chars.peek() {
                if !c.is_ascii_digit() {
                    break;
                }
                rn = rn
                    .saturating_mul(10)
                    .saturating_add((c as i64) - ('0' as i64));
                r_chars.next();
            }
            if vn != rn {
                return if vn > rn { 1 } else { -1 };
            }
        }
    }
    0
}

pub fn bhpkg_vercmp(val: &str, ref_ver: &str) -> Ordering {
    let (v_ep_str, v_ver_str) = val.split_once(':').unwrap_or(("0", val));
    let (r_ep_str, r_ver_str) = ref_ver.split_once(':').unwrap_or(("0", ref_ver));
    let v_epoch: i32 = v_ep_str.parse().unwrap_or(0);
    let r_epoch: i32 = r_ep_str.parse().unwrap_or(0);

    if v_epoch != r_epoch {
        return v_epoch.cmp(&r_epoch);
    }

    let (v_base, v_rev) = v_ver_str.rsplit_once('-').unwrap_or((v_ver_str, ""));
    let (r_base, r_rev) = r_ver_str.rsplit_once('-').unwrap_or((r_ver_str, ""));

    let base_cmp = cmp_string(v_base, r_base);
    if base_cmp != 0 {
        return base_cmp.cmp(&0);
    }
    cmp_string(v_rev, r_rev).cmp(&0)
}

fn eval_constraint(ver: &str, constraint: &str) -> bool {
    if constraint.is_empty() {
        return true;
    }
    let op_len = constraint
        .find(|c: char| c.is_ascii_digit())
        .unwrap_or(constraint.len());
    let (op_str, val_str) = constraint.split_at(op_len);
    let cmp = bhpkg_vercmp(ver, val_str);
    match op_str.trim() {
        ">=" => cmp == Ordering::Greater || cmp == Ordering::Equal,
        "<=" => cmp == Ordering::Less || cmp == Ordering::Equal,
        "==" | "=" => cmp == Ordering::Equal,
        ">" => cmp == Ordering::Greater,
        "<" => cmp == Ordering::Less,
        _ => true,
    }
}

type Literal = i32;

#[derive(Clone, Copy, Debug, PartialEq, Default)]
enum Assignment {
    #[default]
    Unassigned = 0,
    True = 1,
    False = -1,
}

#[derive(Clone, Copy, Debug, Default)]
struct VarData {
    assignment: Assignment,
    decision_level: usize,
    reason_clause_idx: Option<usize>,
    activity: u64,
    phase: Assignment,
}

#[derive(Clone, Debug)]
struct Clause {
    literals: Vec<Literal>,
    activity: u64,
    is_learned: bool,
    lbd: usize,
}

#[derive(Clone, Copy, Debug)]
struct WatchEntry {
    clause_idx: usize,
    blocker: Literal,
}

pub struct SatSolver {
    num_vars: usize,
    var_data: Vec<VarData>,
    clauses: Vec<Clause>,
    watches: Vec<Vec<WatchEntry>>,
    assignment_trail: Vec<Literal>,
    decision_levels: Vec<usize>,
    qhead: usize,
    var_inc: u64,
    clause_inc: u64,
    num_conflicts: usize,
    restart_seq: usize,
    learned_limit: u64,
    seen_vars: Vec<bool>,
    seen_indices: Vec<usize>,
    order_heap: BinaryHeap<(u64, usize)>,
}

fn integer_luby(mut x: usize) -> u64 {
    let mut size = 1;
    let mut seq = 0;
    while size < x + 1 {
        seq += 1;
        size = 2 * size + 1;
    }
    while size - 1 != x {
        size = (size - 1) / 2;
        seq -= 1;
        x %= size;
    }
    1u64.wrapping_shl(seq as u32)
}

impl SatSolver {
    pub fn new(num_vars: usize) -> Self {
        let mut heap = BinaryHeap::with_capacity(num_vars);
        for i in 1..=num_vars {
            heap.push((0, i));
        }

        SatSolver {
            num_vars,
            var_data: vec![VarData::default(); num_vars + 1],
            clauses: Vec::with_capacity(2048),
            watches: vec![Vec::new(); (num_vars + 1) * 2],
            assignment_trail: Vec::with_capacity(num_vars),
            decision_levels: Vec::with_capacity(num_vars),
            qhead: 0,
            var_inc: ACTIVITY_SCALE,
            clause_inc: ACTIVITY_SCALE,
            num_conflicts: 0,
            restart_seq: 1,
            learned_limit: 4000,
            seen_vars: vec![false; num_vars + 1],
            seen_indices: Vec::with_capacity(128),
            order_heap: heap,
        }
    }

    pub fn new_var(&mut self) -> usize {
        self.num_vars += 1;
        self.var_data.push(VarData::default());
        self.watches.push(Vec::new());
        self.watches.push(Vec::new());
        self.seen_vars.push(false);
        self.order_heap.push((0, self.num_vars));
        self.num_vars
    }

    #[inline(always)]
    fn lit_to_idx(lit: Literal) -> usize {
        (lit.abs() as usize) * 2 + (if lit < 0 { 1 } else { 0 })
    }

    #[inline(always)]
    fn get_var_assignment(&self, var: usize) -> Assignment {
        self.var_data[var].assignment
    }

    #[inline(always)]
    fn get_lit_value(&self, lit: Literal) -> Assignment {
        let assign = self.get_var_assignment(lit.abs() as usize);
        if assign == Assignment::Unassigned {
            assign
        } else if (lit > 0 && assign == Assignment::True)
            || (lit < 0 && assign == Assignment::False)
        {
            Assignment::True
        } else {
            Assignment::False
        }
    }

    pub fn assign_literal(&mut self, lit: Literal, reason: Option<usize>, level: usize) {
        let var = lit.abs() as usize;
        self.var_data[var].assignment = if lit > 0 {
            Assignment::True
        } else {
            Assignment::False
        };
        self.var_data[var].decision_level = level;
        self.var_data[var].reason_clause_idx = reason;
        self.assignment_trail.push(lit);
    }

    pub fn add_clause(
        &mut self,
        mut literals: Vec<Literal>,
        is_learned: bool,
        lbd: usize,
    ) -> Result<()> {
        if literals.is_empty() {
            return Err(AppError::Solver("Cannot add empty clause".into()));
        }
        literals.sort_unstable_by_key(|&l| l.abs());
        literals.dedup();

        let mut filtered_lits = Vec::with_capacity(literals.len());
        for &lit in literals.iter() {
            match self.get_lit_value(lit) {
                Assignment::True => return Ok(()),
                Assignment::False => {}
                Assignment::Unassigned => filtered_lits.push(lit),
            }
        }

        if filtered_lits.is_empty() {
            return Err(AppError::Solver(
                "Conflict at base level (Unsatisfiable Graph)".into(),
            ));
        }

        let clause_idx = self.clauses.len();
        let watch0 = filtered_lits.get(0).copied().unwrap_or(0);
        let watch1 = filtered_lits.get(1).copied().unwrap_or(0);

        self.clauses.push(Clause {
            literals: filtered_lits.clone(),
            activity: if is_learned { self.clause_inc } else { 0 },
            is_learned,
            lbd,
        });

        if filtered_lits.len() == 1 {
            self.assign_literal(
                filtered_lits[0],
                Some(clause_idx),
                self.decision_levels.len(),
            );
        } else if filtered_lits.len() >= 2 {
            self.watches[Self::lit_to_idx(watch0)].push(WatchEntry {
                clause_idx,
                blocker: watch1,
            });
            self.watches[Self::lit_to_idx(watch1)].push(WatchEntry {
                clause_idx,
                blocker: watch0,
            });
        }
        Ok(())
    }

    fn propagate(&mut self) -> Option<usize> {
        while self.qhead < self.assignment_trail.len() {
            let p = self.assignment_trail[self.qhead];
            self.qhead += 1;
            let false_lit = -p;
            let watch_idx = Self::lit_to_idx(false_lit);

            let mut i = 0;
            while i < self.watches[watch_idx].len() {
                let entry = self.watches[watch_idx][i];

                if self.get_lit_value(entry.blocker) == Assignment::True {
                    i += 1;
                    continue;
                }

                let mut first_lit = self.clauses[entry.clause_idx].literals[0];
                let mut second_lit = self.clauses[entry.clause_idx].literals[1];

                if first_lit == false_lit {
                    self.clauses[entry.clause_idx].literals.swap(0, 1);
                    std::mem::swap(&mut first_lit, &mut second_lit);
                }

                if self.get_lit_value(first_lit) == Assignment::True {
                    self.watches[watch_idx][i].blocker = first_lit;
                    i += 1;
                    continue;
                }

                let mut found = false;
                let mut new_watch = 0;
                let mut new_watch_idx = 0;

                let num_literals = self.clauses[entry.clause_idx].literals.len();
                for k in 2..num_literals {
                    let lit = self.clauses[entry.clause_idx].literals[k];
                    if self.get_lit_value(lit) != Assignment::False {
                        new_watch = lit;
                        new_watch_idx = k;
                        found = true;
                        break;
                    }
                }

                if found {
                    let clause = &mut self.clauses[entry.clause_idx];
                    clause.literals[new_watch_idx] = false_lit;
                    clause.literals[1] = new_watch;

                    self.watches[Self::lit_to_idx(new_watch)].push(WatchEntry {
                        clause_idx: entry.clause_idx,
                        blocker: first_lit,
                    });
                    self.watches[watch_idx].swap_remove(i);
                } else {
                    if self.get_lit_value(first_lit) == Assignment::False {
                        return Some(entry.clause_idx);
                    } else {
                        self.assign_literal(
                            first_lit,
                            Some(entry.clause_idx),
                            self.decision_levels.len(),
                        );
                        i += 1;
                    }
                }
            }
        }
        None
    }

    fn backtrack(&mut self, level: usize) {
        while !self.assignment_trail.is_empty() {
            let lit = *self.assignment_trail.last().unwrap();
            let var = lit.abs() as usize;
            if self.var_data[var].decision_level <= level {
                break;
            }
            self.var_data[var].phase = self.var_data[var].assignment;
            self.var_data[var].assignment = Assignment::Unassigned;
            self.var_data[var].decision_level = 0;
            self.var_data[var].reason_clause_idx = None;

            self.order_heap.push((self.var_data[var].activity, var));
            self.assignment_trail.pop();
        }
        self.qhead = self.assignment_trail.len();
        self.decision_levels.truncate(level);
    }

    fn analyze_conflict(&mut self, mut conflict_clause_idx: usize) -> (Vec<Literal>, usize, usize) {
        self.num_conflicts += 1;
        self.clauses[conflict_clause_idx].activity += self.clause_inc;

        let mut learned_clause_lits = vec![];
        let mut path_c = 0;
        let mut trail_idx = self.assignment_trail.len() - 1;
        let current_dl = self.decision_levels.len();

        loop {
            let conflict_clause = &self.clauses[conflict_clause_idx];
            for &lit in conflict_clause.literals.iter() {
                let var = lit.abs() as usize;
                if !self.seen_vars[var] {
                    self.seen_vars[var] = true;
                    self.seen_indices.push(var);
                    self.var_data[var].activity += self.var_inc;
                    self.order_heap.push((self.var_data[var].activity, var));

                    if self.var_data[var].decision_level == current_dl {
                        path_c += 1;
                    } else {
                        learned_clause_lits.push(lit);
                    }
                }
            }

            self.var_inc = (self.var_inc * 105) / 100;
            self.clause_inc = (self.clause_inc * 1001) / 1000;

            if self.var_inc > u64::MAX / 4 {
                for vd in &mut self.var_data {
                    vd.activity >>= 10;
                }
                self.var_inc >>= 10;
            }
            if self.clause_inc > u64::MAX / 4 {
                for c in &mut self.clauses {
                    c.activity >>= 10;
                }
                self.clause_inc >>= 10;
            }

            path_c -= 1;
            if path_c <= 0 || trail_idx == 0 {
                break;
            }

            let lit_on_trail = self.assignment_trail[trail_idx];
            let var_on_trail = lit_on_trail.abs() as usize;

            if let Some(reason_idx) = self.var_data[var_on_trail].reason_clause_idx {
                conflict_clause_idx = reason_idx;
            }
            trail_idx -= 1;
        }

        learned_clause_lits.push(-self.assignment_trail[trail_idx]);
        for &var in &self.seen_indices {
            self.seen_vars[var] = false;
        }
        self.seen_indices.clear();

        let mut backtrack_level = 0;
        let mut dl_in_learned: Vec<usize> = learned_clause_lits
            .iter()
            .map(|&l| self.var_data[l.abs() as usize].decision_level)
            .collect();
        dl_in_learned.sort_unstable();
        dl_in_learned.dedup();

        let lbd = dl_in_learned.len();
        if dl_in_learned.len() > 1 {
            backtrack_level = dl_in_learned[dl_in_learned.len() - 2];
        }
        (learned_clause_lits, backtrack_level, lbd)
    }

    fn reduce_db(&mut self) {
        let mut clauses_to_delete = Vec::new();
        for (i, c) in self.clauses.iter().enumerate() {
            let is_reason = self.var_data.iter().any(|v| v.reason_clause_idx == Some(i));
            if !c.is_learned || is_reason {
                continue;
            }
            clauses_to_delete.push((i, c.lbd, c.activity));
        }

        clauses_to_delete.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.2.cmp(&b.2)));
        let delete_count = clauses_to_delete.len() / 2;
        let to_delete: HashSet<usize> = clauses_to_delete
            .into_iter()
            .take(delete_count)
            .map(|(i, ..)| i)
            .collect();

        let mut old_to_new = vec![None; self.clauses.len()];
        let mut compacted = Vec::with_capacity(self.clauses.len() - to_delete.len());

        for (i, c) in self.clauses.drain(..).enumerate() {
            if to_delete.contains(&i) {
                continue;
            }
            old_to_new[i] = Some(compacted.len());
            compacted.push(c);
        }
        self.clauses = compacted;

        for w in &mut self.watches {
            w.clear();
        }
        for (i, c) in self.clauses.iter().enumerate() {
            if c.literals.len() >= 2 {
                self.watches[Self::lit_to_idx(c.literals[0])].push(WatchEntry {
                    clause_idx: i,
                    blocker: c.literals[1],
                });
                self.watches[Self::lit_to_idx(c.literals[1])].push(WatchEntry {
                    clause_idx: i,
                    blocker: c.literals[0],
                });
            }
        }

        for vd in &mut self.var_data {
            if let Some(old_idx) = vd.reason_clause_idx {
                vd.reason_clause_idx = old_to_new[old_idx];
            }
        }
    }

    pub fn solve(&mut self, ctx: &AppContext) -> Result<Vec<Literal>> {
        let mut current_restart_limit = (integer_luby(self.restart_seq) * 100) as usize;

        loop {
            if ctx.is_interrupted() {
                return Err(AppError::Solver("Solver interrupted".into()));
            }

            if let Some(conflict_clause_idx) = self.propagate() {
                if self.decision_levels.is_empty() {
                    return Err(AppError::Solver(
                        "UNSAT: Constraints inherently conflicting".into(),
                    ));
                }

                let (learned, backtrack_level, lbd) = self.analyze_conflict(conflict_clause_idx);
                self.add_clause(learned.clone(), true, lbd)?;
                self.backtrack(backtrack_level);
            } else {
                if self.assignment_trail.len() == self.num_vars {
                    return Ok(self.assignment_trail.clone());
                }

                if self.num_conflicts >= current_restart_limit {
                    self.backtrack(0);
                    self.restart_seq += 1;
                    current_restart_limit =
                        self.num_conflicts + (integer_luby(self.restart_seq) * 100) as usize;

                    if (self.clauses.len() as u64) > self.learned_limit {
                        self.reduce_db();
                        self.learned_limit = (self.learned_limit * 11) / 10;
                    }
                }

                let mut best_var = 0;
                while let Some(&(act, var)) = self.order_heap.peek() {
                    if self.get_var_assignment(var) != Assignment::Unassigned {
                        self.order_heap.pop();
                        continue;
                    }
                    if act == self.var_data[var].activity {
                        best_var = var;
                        break;
                    } else {
                        self.order_heap.pop();
                    }
                }

                if best_var == 0 {
                    for i in 1..=self.num_vars {
                        if self.get_var_assignment(i) == Assignment::Unassigned {
                            best_var = i;
                            break;
                        }
                    }
                }

                if best_var != 0 {
                    self.decision_levels.push(self.assignment_trail.len());
                    let polarity = if self.var_data[best_var].phase == Assignment::False {
                        -1
                    } else {
                        1
                    };
                    self.assign_literal(
                        (best_var as Literal) * polarity,
                        None,
                        self.decision_levels.len(),
                    );
                } else {
                    return Ok(self.assignment_trail.clone());
                }
            }
        }
    }
}

fn tarjan_topological_sort(assignment: &[PackageRef], ctx: &AppContext) -> Vec<PackageRef> {
    let count = assignment.len();
    if count == 0 {
        return Vec::new();
    }

    let mut adj = vec![Vec::new(); count];
    for i in 0..count {
        let p = &assignment[i];
        for j in 0..count {
            if i == j {
                continue;
            }
            let dep = &assignment[j];
            let mut is_direct_dep = false;

            for (idx, dep_name) in p.dep_names.iter().enumerate() {
                if dep_name == &dep.name && eval_constraint(&dep.version, &p.dep_constraints[idx]) {
                    is_direct_dep = true;
                    break;
                }
            }

            if !is_direct_dep && !p.is_installed && p.pkg_type == "source" {
                for (idx, dep_name) in p.makedep_names.iter().enumerate() {
                    if dep_name == &dep.name
                        && eval_constraint(&dep.version, &p.makedep_constraints[idx])
                    {
                        is_direct_dep = true;
                        break;
                    }
                }
            }

            if !is_direct_dep {
                for provided_by_dep in dep.provides.iter() {
                    for (idx, dep_name) in p.dep_names.iter().enumerate() {
                        if dep_name == provided_by_dep
                            && eval_constraint(&dep.version, &p.dep_constraints[idx])
                        {
                            is_direct_dep = true;
                            break;
                        }
                    }
                    if is_direct_dep {
                        break;
                    }
                }
            }
            if is_direct_dep {
                adj[i].push(j);
            }
        }
    }

    let mut index = 0;
    let mut stack: Vec<usize> = Vec::new();
    let mut indices = vec![None; count];
    let mut lowlinks = vec![0; count];
    let mut on_stack = vec![false; count];
    let mut sccs = Vec::new();

    fn strongconnect(
        v: usize,
        index: &mut usize,
        stack: &mut Vec<usize>,
        indices: &mut Vec<Option<usize>>,
        lowlinks: &mut Vec<usize>,
        on_stack: &mut Vec<bool>,
        sccs: &mut Vec<Vec<usize>>,
        adj: &Vec<Vec<usize>>,
    ) {
        indices[v] = Some(*index);
        lowlinks[v] = *index;
        *index += 1;
        stack.push(v);
        on_stack[v] = true;

        for &w in &adj[v] {
            if indices[w].is_none() {
                strongconnect(w, index, stack, indices, lowlinks, on_stack, sccs, adj);
                lowlinks[v] = std::cmp::min(lowlinks[v], lowlinks[w]);
            } else if on_stack[w] {
                lowlinks[v] = std::cmp::min(lowlinks[v], indices[w].unwrap());
            }
        }

        if lowlinks[v] == indices[v].unwrap() {
            let mut scc = Vec::new();
            loop {
                let w = stack.pop().unwrap();
                on_stack[w] = false;
                scc.push(w);
                if w == v {
                    break;
                }
            }
            sccs.push(scc);
        }
    }

    for i in 0..count {
        if indices[i].is_none() {
            strongconnect(
                i,
                &mut index,
                &mut stack,
                &mut indices,
                &mut lowlinks,
                &mut on_stack,
                &mut sccs,
                &adj,
            );
        }
    }

    let mut order = Vec::with_capacity(count);
    for scc in sccs.into_iter() {
        if scc.len() > 1 {
            let cycle_names: Vec<&str> = scc
                .iter()
                .map(|&idx| assignment[idx].name.as_str())
                .collect();
            ctx.print_warn(&format!(
                "Circular dependency sequence natively grouped: {:?}",
                cycle_names
            ));
        }
        for &v in &scc {
            order.push(assignment[v].clone());
        }
    }
    order
}

pub trait PackageDatabase {
    fn fetch_all_versions(&self, name: &str, ctx: &AppContext) -> Result<Vec<PackageRef>>;
    fn fetch_providers(&self, provides_name: &str, ctx: &AppContext) -> Result<Vec<PackageRef>>;
    fn remove_package(&mut self, name: &str, ctx: &AppContext) -> Result<bool>;
    fn register_package(
        &mut self,
        pkg: &crate::types::Package,
        staging_dir: &std::path::Path,
        ctx: &AppContext,
    ) -> Result<()>;
    fn check_conflict(&self, filepath: &str, pkg_name: &str) -> Result<Option<String>>;
    fn get_file_hash(&self, filepath: &str) -> Result<Option<String>>;
    fn reconstruct_to_staging(&self, pkg_name: &str, staging_dir: &std::path::Path) -> Result<()>;
}

pub fn resolve_dependencies(
    root: &PackageRef,
    db: &mut dyn PackageDatabase,
    ctx: &AppContext,
) -> Result<Vec<PackageRef>> {
    let mut universe: Vec<PackageRef> = Vec::new();
    let mut name_to_versions: HashMap<String, Vec<usize>> = HashMap::new();
    let mut pkg_to_id: HashMap<(String, String), usize> = HashMap::new();

    let mut queue: Vec<PackageRef> = vec![root.clone()];
    let mut qhead = 0;

    while qhead < queue.len() {
        if ctx.is_interrupted() {
            return Err(AppError::Solver("Interrupted".into()));
        }
        let pkg = queue[qhead].clone();
        qhead += 1;

        let key = (pkg.name.clone(), pkg.version.clone());
        if pkg_to_id.contains_key(&key) {
            continue;
        }

        let var_idx = universe.len() + 1;
        pkg_to_id.insert(key, var_idx);
        universe.push(pkg.clone());
        name_to_versions
            .entry(pkg.name.clone())
            .or_default()
            .push(var_idx);

        for cand in db.fetch_all_versions(&pkg.name, ctx)? {
            let c_key = (cand.name.clone(), cand.version.clone());
            if !pkg_to_id.contains_key(&c_key) {
                queue.push(cand);
            }
        }

        let types = if !pkg.is_installed && pkg.pkg_type == "source" {
            vec![&pkg.dep_names, &pkg.makedep_names]
        } else {
            vec![&pkg.dep_names]
        };

        for names in types {
            for name in names.iter() {
                for cand in db.fetch_all_versions(name, ctx)? {
                    let c_key = (cand.name.clone(), cand.version.clone());
                    if !pkg_to_id.contains_key(&c_key) {
                        queue.push(cand);
                    }
                }
                for provider in db.fetch_providers(name, ctx)? {
                    let p_key = (provider.name.clone(), provider.version.clone());
                    if !pkg_to_id.contains_key(&p_key) {
                        queue.push(provider);
                    }
                }
            }
        }
    }

    let mut solver = SatSolver::new(universe.len());
    let root_key = (root.name.clone(), root.version.clone());
    let root_idx = *pkg_to_id
        .get(&root_key)
        .ok_or_else(|| AppError::Solver("Root package not found".into()))?;

    solver.assign_literal(root_idx as Literal, None, 0);
    solver.decision_levels.push(0);

    for var_indices in name_to_versions.values() {
        let n = var_indices.len();
        if n <= 1 {
            continue;
        }
        if n <= 4 {
            for i in 0..n {
                for j in (i + 1)..n {
                    solver.add_clause(
                        vec![
                            -((var_indices[i]) as Literal),
                            -((var_indices[j]) as Literal),
                        ],
                        false,
                        0,
                    )?;
                }
            }
        } else {
            let mut s_vars = Vec::with_capacity(n - 1);
            for _ in 0..(n - 1) {
                s_vars.push(solver.new_var() as Literal);
            }

            let x = |i: usize| var_indices[i] as Literal;

            solver.add_clause(vec![-x(0), s_vars[0]], false, 0)?;
            for i in 1..(n - 1) {
                solver.add_clause(vec![-x(i), s_vars[i]], false, 0)?;
                solver.add_clause(vec![-s_vars[i - 1], s_vars[i]], false, 0)?;
                solver.add_clause(vec![-x(i), -s_vars[i - 1]], false, 0)?;
            }
            solver.add_clause(vec![-x(n - 1), -s_vars[n - 2]], false, 0)?;
        }
    }

    for (idx, pkg) in universe.iter().enumerate() {
        let p_var = (idx + 1) as Literal;
        let reqs = if !pkg.is_installed && pkg.pkg_type == "source" {
            vec![
                (&pkg.dep_names, &pkg.dep_constraints),
                (&pkg.makedep_names, &pkg.makedep_constraints),
            ]
        } else {
            vec![(&pkg.dep_names, &pkg.dep_constraints)]
        };

        for (dep_names, dep_constraints) in reqs {
            for (d_idx, dep_name) in dep_names.iter().enumerate() {
                let mut clause_lits = vec![-p_var];
                let constraint = &dep_constraints[d_idx];

                for (cand_idx, potential_dep) in universe.iter().enumerate() {
                    let d_var = (cand_idx + 1) as Literal;
                    if (&potential_dep.name == dep_name
                        && eval_constraint(&potential_dep.version, constraint))
                        || potential_dep.provides.contains(dep_name)
                    {
                        clause_lits.push(d_var);
                    }
                }
                solver.add_clause(clause_lits, false, 0)?;
            }
        }

        for conflict_name in pkg.conflicts.iter() {
            for (cand_idx, conflict_pkg) in universe.iter().enumerate() {
                let c_var = (cand_idx + 1) as Literal;
                if p_var.abs() == c_var.abs() {
                    continue;
                }
                if &conflict_pkg.name == conflict_name
                    || conflict_pkg.provides.contains(conflict_name)
                {
                    solver.add_clause(vec![-p_var, -c_var], false, 0)?;
                }
            }
        }
    }

    ctx.print_msg(&format!(
        "Solving multi-version graph ({} packages)...",
        universe.len()
    ));
    let solution_lits = solver.solve(ctx)?;

    let mut assigned_packages = Vec::new();
    let mut installed_packages = Vec::new();

    for lit in solution_lits {
        if lit > 0 {
            let var_idx = (lit as usize) - 1;
            if let Some(pkg) = universe.get(var_idx) {
                assigned_packages.push(pkg.clone());
            }
        }
    }

    for pkg in &assigned_packages {
        for obs_name in pkg.obsoletes.iter() {
            ctx.print_warn(&format!(
                "'{}' obsoletes '{}'. Marking for removal.",
                pkg.name, obs_name
            ));
            db.remove_package(obs_name, ctx)?;
        }
        if !pkg.is_installed {
            installed_packages.push(pkg.clone());
        }
    }

    Ok(tarjan_topological_sort(&installed_packages, ctx))
}
