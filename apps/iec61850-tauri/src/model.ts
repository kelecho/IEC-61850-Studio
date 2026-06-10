// Construye el árbol del modelo de datos (LD → LN → DO/SDO → DA) a partir de las
// referencias planas que devuelve el backend, p. ej.
// "IED1LD0/MMXU1.A.phsA.cVal.mag.f[MX]".

export type DomainItems = { domain: string; items: string[] };

export type TreeNode = {
  id: string;
  label: string;
  fc?: string | null; // sólo en hojas/atributos legibles
  reference?: string | null; // referencia completa (nodos legibles)
  cdc?: string | null; // clase de datos común (sólo en DO, vista SCL)
  ty?: string | null; // tipo básico (sólo en DA hoja, vista SCL)
  desc?: string | null; // descripción legible (desc en SCL)
  children: TreeNode[];
};

function parseRef(ref: string): { ln: string; segs: string[]; fc?: string } | null {
  const slash = ref.indexOf("/");
  if (slash < 0) return null;
  let rest = ref.slice(slash + 1);
  let fc: string | undefined;
  const lb = rest.indexOf("[");
  if (lb >= 0 && rest.endsWith("]")) {
    fc = rest.slice(lb + 1, rest.length - 1);
    rest = rest.slice(0, lb);
  }
  const parts = rest.split(".");
  return { ln: parts[0], segs: parts.slice(1), fc };
}

export function buildTree(domains: DomainItems[], groupByFc = false): TreeNode[] {
  const roots: TreeNode[] = [];
  const byId = new Map<string, TreeNode>();
  const ensure = (siblings: TreeNode[], id: string, label: string): TreeNode => {
    let n = byId.get(id);
    if (!n) {
      n = { id, label, children: [] };
      byId.set(id, n);
      siblings.push(n);
    }
    return n;
  };

  for (const d of domains) {
    const ld = ensure(roots, `LD:${d.domain}`, d.domain);
    for (const ref of d.items) {
      const p = parseRef(ref);
      if (!p) continue;
      const ln = ensure(ld.children, `${ld.id}/${p.ln}`, p.ln);
      // Vista opcional agrupada por restricción funcional (FC).
      const container =
        groupByFc && p.fc ? ensure(ln.children, `${ln.id}#${p.fc}`, p.fc) : ln;
      if (p.segs.length === 0) {
        container.reference = ref;
        container.fc = p.fc;
        continue;
      }
      let parent = container;
      let path = container.id;
      p.segs.forEach((seg, i) => {
        path += `.${seg}`;
        const node = ensure(parent.children, path, seg);
        if (i === p.segs.length - 1) {
          node.reference = ref;
          node.fc = p.fc;
        }
        parent = node;
      });
    }
  }

  // Carpetas (con hijos) primero, luego hojas; alfabético dentro de cada grupo.
  const sortRec = (nodes: TreeNode[]) => {
    nodes.sort((a, b) => {
      const af = a.children.length > 0 ? 0 : 1;
      const bf = b.children.length > 0 ? 0 : 1;
      return af !== bf ? af - bf : a.label.localeCompare(b.label);
    });
    nodes.forEach((n) => sortRec(n.children));
  };
  sortRec(roots);
  return roots;
}

/// Dada una referencia hoja, localiza las referencias de `q` (calidad) y `t`
/// (timestamp) del DO/DA que la contiene, buscando el prefijo más profundo que
/// tenga hermanos `q`/`t` en el namespace descubierto.
export function findQT(domains: DomainItems[], ref: string): { q?: string; t?: string } {
  const set = new Set<string>();
  for (const d of domains) for (const it of d.items) set.add(it);
  const p = parseRef(ref);
  if (!p) return {};
  const ld = ref.slice(0, ref.indexOf("/"));
  const fcs = p.fc ? `[${p.fc}]` : "";
  for (let k = p.segs.length - 1; k >= 1; k--) {
    const prefix = `${ld}/${p.ln}.${p.segs.slice(0, k).join(".")}`;
    const q = `${prefix}.q${fcs}`;
    const t = `${prefix}.t${fcs}`;
    if (set.has(q) || set.has(t)) {
      return { q: set.has(q) ? q : undefined, t: set.has(t) ? t : undefined };
    }
  }
  return {};
}

/// Recolecta todas las referencias de hoja (atributos legibles) de un árbol.
export function collectLeafRefs(nodes: TreeNode[]): string[] {
  const out: string[] = [];
  const rec = (ns: TreeNode[]) => {
    for (const n of ns) {
      if (n.reference) out.push(n.reference);
      rec(n.children);
    }
  };
  rec(nodes);
  return out;
}

/// Filtra el árbol por texto (en etiqueta o referencia), conservando ancestros.
export function filterTree(nodes: TreeNode[], query: string): TreeNode[] {
  const q = query.trim().toLowerCase();
  if (!q) return nodes;
  const rec = (ns: TreeNode[]): TreeNode[] => {
    const out: TreeNode[] = [];
    for (const n of ns) {
      const kids = rec(n.children);
      const self =
        n.label.toLowerCase().includes(q) ||
        (n.reference?.toLowerCase().includes(q) ?? false);
      if (self || kids.length > 0) out.push({ ...n, children: kids });
    }
    return out;
  };
  return rec(nodes);
}
