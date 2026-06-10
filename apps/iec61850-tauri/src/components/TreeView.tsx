import { useState } from "react";
import {
  Badge,
  Box,
  Group,
  ScrollArea,
  Text,
  UnstyledButton,
  useComputedColorScheme,
} from "@mantine/core";
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

/** Color de familia por papel del nodo (LD / LN / DO / DA). */
function familyColor(node: TreeNode, role: string): string {
  if (role === "ld") return "indigo";
  if (role === "ln") {
    const cls = lnClassOf(node.label) ?? "";
    return LN_CLASS_COLOR[cls] ?? LN_COLOR[lnIconKey(node.label)] ?? "gray";
  }
  if (role === "do") return DO_COLOR[cdcCategory(node.cdc)];
  return fcColor(node.fc); // DA
}

function Node({
  node,
  depth,
  selected,
  values,
  forceOpen,
  maxDepth,
  onSelect,
}: {
  node: TreeNode;
  depth: number;
  selected: string | null;
  values?: Map<string, string>;
  forceOpen?: boolean;
  maxDepth: number;
  onSelect: (node: TreeNode) => void;
}) {
  const hasChildren = node.children.length > 0;
  const expandable = hasChildren && depth < maxDepth;
  const [open, setOpen] = useState(depth < 2 || !!forceOpen);
  // En tema claro subimos el tono (.7) para más contraste; en oscuro .6.
  const scheme = useComputedColorScheme("light");
  const shade = scheme === "light" ? "7" : "6";
  const isSel = node.id === selected;
  const value = node.reference ? values?.get(node.reference) : undefined;
  const meaning =
    node.desc ?? doDesc(node.label) ?? cdcDesc(node.cdc) ?? (hasChildren ? lnDesc(node.label) : null);

  const role = depth === 0 ? "ld" : depth === 1 && hasChildren ? "ln" : hasChildren ? "do" : "da";
  const color = familyColor(node, role);
  const isLd = role === "ld";
  const isLn = role === "ln";
  const padY = isLd ? 6 : isLn ? 4 : 3;
  const textFw = isLd ? 700 : isLn ? 600 : role === "do" ? 500 : 400;
  const textSize = isLd ? "md" : "sm";

  return (
    <Box style={isLd && depth === 0 ? { marginTop: 8 } : undefined}>
      <UnstyledButton
        onClick={() => {
          if (expandable) setOpen((o) => !o);
          else onSelect(node);
        }}
        style={{
          display: "block",
          width: "100%",
          paddingLeft: depth * 18 + 6,
          paddingTop: padY,
          paddingBottom: padY,
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
        <Group gap={6} wrap="nowrap">
          {expandable ? (
            open ? (
              <IconChevronDown size={14} color="var(--mantine-color-dimmed)" />
            ) : (
              <IconChevronRight size={14} color="var(--mantine-color-dimmed)" />
            )
          ) : (
            <Box w={14} />
          )}
          <Text size={textSize} fw={textFw} c={`${color}.${shade}`} ff="monospace" style={{ whiteSpace: "nowrap" }}>
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
      {open &&
        expandable &&
        node.children.map((c) => (
          <Node
            key={c.id}
            node={c}
            depth={depth + 1}
            selected={selected}
            values={values}
            forceOpen={forceOpen}
            maxDepth={maxDepth}
            onSelect={onSelect}
          />
        ))}
    </Box>
  );
}

export function TreeView({ data, selected, values, forceOpen, maxDepth, onSelect }: Props) {
  if (data.length === 0) {
    return (
      <Text c="dimmed" size="sm">
        (sin coincidencias)
      </Text>
    );
  }
  return (
    <ScrollArea h="100%" type="auto">
      {data.map((n) => (
        <Node
          key={n.id}
          node={n}
          depth={0}
          selected={selected}
          values={values}
          forceOpen={forceOpen}
          maxDepth={maxDepth ?? Number.POSITIVE_INFINITY}
          onSelect={onSelect}
        />
      ))}
    </ScrollArea>
  );
}
