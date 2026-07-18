import { memo, useEffect, useMemo, useRef, useState } from "react";
import { Badge, Box, Group, Text, UnstyledButton, useComputedColorScheme } from "@mantine/core";
import { IconChevronDown, IconChevronRight } from "@tabler/icons-react";
import type { TreeNode } from "../model";
import { cdcCategory, cdcDesc, doDesc, fcColor, lnClassOf, lnDesc, lnIconKey } from "../iec61850";

// Color por clase/grupo de LN (las clases concretas tienen prioridad).
const LN_CLASS_COLOR: Record<string, string> = { RSYN: "cyan", RREC: "orange", RBRF: "red" };
const LN_COLOR: Record<string, string> = {
  protection: "red",
  control: "orange",
  measure: "teal",
  switch: "blue",
  io: "grape",
  transformer: "yellow",
  supervision: "cyan",
  auto: "indigo",
  interface: "gray",
  common: "gray",
  equipment: "lime",
};
// Color de un DO según la categoría de su CDC.
const DO_COLOR: Record<string, string> = {
  measured: "teal",
  status: "blue",
  control: "orange",
  setting: "grape",
  description: "gray",
  do: "gray",
};

type Props = {
  data: TreeNode[];
  selected: string | null;
  values?: Map<string, string>;
  forceOpen?: boolean;
  /** Profundidad máxima navegable: los nodos a esa profundidad se vuelven hojas
   *  seleccionables (no se expanden), p. ej. 2 = parar en el DO. */
  maxDepth?: number;
  onSelect: (node: TreeNode) => void;
};

type Role = "ld" | "ln" | "do" | "da";

/** Color de familia por papel del nodo (LD / LN / DO / DA); acentúa bordes y
 *  badges — el texto de las etiquetas queda en el color por defecto del tema. */
function familyColor(node: TreeNode, role: Role): string {
  if (role === "ld") return "indigo";
  if (role === "ln") {
    const cls = lnClassOf(node.label) ?? "";
    return LN_CLASS_COLOR[cls] ?? LN_COLOR[lnIconKey(node.label)] ?? "gray";
  }
  if (role === "do") return DO_COLOR[cdcCategory(node.cdc)];
  return fcColor(node.fc); // DA
}

/** Altura fija de fila: permite virtualizar con aritmética simple. */
const ROW_H = 28;
/** Filas extra pintadas por encima/debajo del viewport. */
const OVERSCAN = 12;
/** Con menos nodos que esto, LD y LN arrancan desplegados (modelos pequeños). */
const AUTO_EXPAND_LIMIT = 1500;

type FlatRow = {
  node: TreeNode;
  depth: number;
  expandable: boolean;
  role: Role;
};

function flatten(
  data: TreeNode[],
  expanded: ReadonlySet<string>,
  forceOpen: boolean,
  maxDepth: number,
): FlatRow[] {
  const out: FlatRow[] = [];
  const walk = (nodes: TreeNode[], depth: number) => {
    for (const n of nodes) {
      const hasChildren = n.children.length > 0;
      const expandable = hasChildren && depth < maxDepth;
      const role: Role = depth === 0 ? "ld" : depth === 1 && hasChildren ? "ln" : hasChildren ? "do" : "da";
      out.push({ node: n, depth, expandable, role });
      if (expandable && (forceOpen || expanded.has(n.id))) walk(n.children, depth + 1);
    }
  };
  walk(data, 0);
  return out;
}

function countNodes(nodes: TreeNode[]): number {
  let n = 0;
  const walk = (ns: TreeNode[]) => {
    for (const t of ns) {
      n += 1;
      walk(t.children);
    }
  };
  walk(nodes);
  return n;
}

const Row = memo(function Row({
  row,
  top,
  open,
  isSel,
  value,
  shade,
  onToggle,
  onSelect,
}: {
  row: FlatRow;
  top: number;
  open: boolean;
  isSel: boolean;
  value: string | undefined;
  shade: string;
  onToggle: (id: string) => void;
  onSelect: (node: TreeNode) => void;
}) {
  const { node, depth, expandable, role } = row;
  const color = familyColor(node, role);
  const isLd = role === "ld";
  const isLn = role === "ln";
  const meaning =
    node.desc ?? doDesc(node.label) ?? cdcDesc(node.cdc) ?? (node.children.length > 0 ? lnDesc(node.label) : null);

  return (
    <UnstyledButton
      onClick={() => {
        if (expandable) onToggle(node.id);
        else onSelect(node);
      }}
      style={{
        position: "absolute",
        top,
        left: 0,
        right: 0,
        height: ROW_H,
        display: "flex",
        alignItems: "center",
        paddingLeft: depth * 18 + 6,
        borderRadius: 4,
        borderTop: isLd ? "1px solid var(--mantine-color-default-border)" : undefined,
        borderBottom: "1px solid rgba(128,128,128,0.12)", // separador de renglón tenue
        borderLeft: isLn ? `2px solid var(--mantine-color-${color}-5)` : undefined,
        background: isSel
          ? "var(--mantine-color-blue-light)"
          : isLd
            ? "var(--mantine-color-default-hover)"
            : undefined,
      }}
    >
      <Group gap={6} wrap="nowrap" style={{ overflow: "hidden" }}>
        {expandable ? (
          open ? (
            <IconChevronDown size={14} color="var(--mantine-color-dimmed)" style={{ flexShrink: 0 }} />
          ) : (
            <IconChevronRight size={14} color="var(--mantine-color-dimmed)" style={{ flexShrink: 0 }} />
          )
        ) : (
          <Box w={14} style={{ flexShrink: 0 }} />
        )}
        <Text
          size="sm"
          fw={isLd ? 700 : isLn ? 600 : role === "do" ? 500 : 400}
          ff="monospace"
          style={{ whiteSpace: "nowrap" }}
        >
          {node.label}
        </Text>
        {node.cdc && (
          <Badge size="sm" variant="outline" color={DO_COLOR[cdcCategory(node.cdc)] ?? "grape"}>
            {node.cdc}
          </Badge>
        )}
        {node.fc && (
          <Badge size="sm" variant="light" color={fcColor(node.fc)}>
            {node.fc}
          </Badge>
        )}
        {node.ty && (
          <Text size="sm" c="dimmed" style={{ whiteSpace: "nowrap" }}>
            {node.ty}
          </Text>
        )}
        {value !== undefined && (
          <Text size="sm" ff="monospace" c={`teal.${shade}`} fw={600} style={{ whiteSpace: "nowrap" }}>
            = {value}
          </Text>
        )}
        {meaning && (
          <Text size="sm" c="dimmed" fs="italic" style={{ whiteSpace: "nowrap" }}>
            — {meaning}
          </Text>
        )}
      </Group>
    </UnstyledButton>
  );
});

export function TreeView({ data, selected, values, forceOpen, maxDepth, onSelect }: Props) {
  const depthMax = maxDepth ?? Number.POSITIVE_INFINITY;
  const scheme = useComputedColorScheme("light");
  // En tema claro subimos el tono (.7) para más contraste; en oscuro .6.
  const shade = scheme === "light" ? "7" : "6";

  // Modelos pequeños: LD y LN desplegados de inicio (comportamiento clásico).
  // Modelos grandes (CID/SCD reales): todo plegado — el usuario abre lo que mira.
  const initialExpanded = useMemo(() => {
    const set = new Set<string>();
    if (countNodes(data) <= AUTO_EXPAND_LIMIT) {
      for (const ld of data) {
        set.add(ld.id);
        for (const ln of ld.children) set.add(ln.id);
      }
    } else {
      for (const ld of data) set.add(ld.id);
    }
    return set;
  }, [data]);
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(initialExpanded);
  useEffect(() => setExpanded(initialExpanded), [initialExpanded]);

  const rows = useMemo(
    () => flatten(data, expanded, !!forceOpen, depthMax),
    [data, expanded, forceOpen, depthMax],
  );

  // Virtualización: solo se montan las filas dentro del viewport (+overscan).
  const viewportRef = useRef<HTMLDivElement | null>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewH, setViewH] = useState(600);
  useEffect(() => {
    const el = viewportRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setViewH(el.clientHeight));
    ro.observe(el);
    setViewH(el.clientHeight);
    return () => ro.disconnect();
  }, []);

  const onToggle = useMemo(
    () => (id: string) => {
      setExpanded((prev) => {
        const next = new Set(prev);
        if (next.has(id)) next.delete(id);
        else next.add(id);
        return next;
      });
    },
    [],
  );

  if (data.length === 0) {
    return (
      <Text c="dimmed" size="sm">
        (sin coincidencias)
      </Text>
    );
  }

  const first = Math.max(0, Math.floor(scrollTop / ROW_H) - OVERSCAN);
  const last = Math.min(rows.length, Math.ceil((scrollTop + viewH) / ROW_H) + OVERSCAN);

  return (
    <div
      ref={viewportRef}
      onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}
      style={{ height: "100%", overflowY: "auto", overflowX: "hidden" }}
    >
      <div style={{ position: "relative", height: rows.length * ROW_H }}>
        {rows.slice(first, last).map((row, i) => (
          <Row
            key={row.node.id}
            row={row}
            top={(first + i) * ROW_H}
            open={forceOpen || expanded.has(row.node.id)}
            isSel={row.node.id === selected}
            value={row.node.reference ? values?.get(row.node.reference) : undefined}
            shade={shade}
            onToggle={onToggle}
            onSelect={onSelect}
          />
        ))}
      </div>
    </div>
  );
}
