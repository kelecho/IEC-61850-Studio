import { useState } from "react";
import { Badge, Box, Group, Text, UnstyledButton } from "@mantine/core";
import { IconChevronDown, IconChevronRight } from "@tabler/icons-react";
import type { TreeNode } from "../model";
import { cdcCategory, cdcDesc, doDesc, fcColor } from "../iec61850";

const CAT_COLOR: Record<string, string> = {
  measured: "teal",
  status: "blue",
  control: "orange",
  setting: "grape",
  description: "gray",
  do: "gray",
};

type RowProps = {
  node: TreeNode;
  values: Map<string, string>;
  depth: number;
  picked: string | null;
  onPick: (node: TreeNode) => void;
};

function AttrRow({ node, values, depth, picked, onPick }: RowProps) {
  const hasKids = node.children.length > 0;
  const [open, setOpen] = useState(depth < 2);
  const meaning = node.desc ?? doDesc(node.label) ?? cdcDesc(node.cdc);

  if (!hasKids) {
    const val = node.reference ? values.get(node.reference) : undefined;
    const isSel = node.id === picked;
    return (
      <UnstyledButton
        onClick={() => onPick(node)}
        style={{
          display: "block",
          width: "100%",
          paddingLeft: depth * 16 + 6,
          paddingTop: 3,
          paddingBottom: 3,
          borderBottom: "1px solid rgba(128,128,128,0.1)",
          background: isSel ? "var(--mantine-color-blue-light)" : undefined,
        }}
      >
        <Group gap="sm" wrap="nowrap">
          <Box w={14} />
          <Text size="sm" ff="monospace" w={150} style={{ flexShrink: 0 }}>
            {node.label}
          </Text>
          {node.fc && (
            <Badge size="sm" variant="light" color={fcColor(node.fc)}>
              {node.fc}
            </Badge>
          )}
          <Text
            size="sm"
            ff="monospace"
            c={val !== undefined ? "teal.6" : "dimmed"}
            fw={600}
            style={{ minWidth: 0, wordBreak: "break-all" }}
          >
            {val ?? "—"}
          </Text>
          {meaning && (
            <Text size="xs" c="dimmed" fs="italic" style={{ whiteSpace: "nowrap" }}>
              — {meaning}
            </Text>
          )}
        </Group>
      </UnstyledButton>
    );
  }

  // Grupo (SDO / estructura) colapsable.
  const color = CAT_COLOR[cdcCategory(node.cdc)] ?? "gray";
  return (
    <Box>
      <UnstyledButton
        onClick={() => setOpen((o) => !o)}
        style={{ display: "block", width: "100%", paddingLeft: depth * 16 + 6, paddingTop: 3, paddingBottom: 3 }}
      >
        <Group gap="sm" wrap="nowrap">
          {open ? (
            <IconChevronDown size={14} color="var(--mantine-color-dimmed)" />
          ) : (
            <IconChevronRight size={14} color="var(--mantine-color-dimmed)" />
          )}
          <Text size="sm" fw={600} ff="monospace" c={`${color}.6`} style={{ whiteSpace: "nowrap" }}>
            {node.label}
          </Text>
          {node.cdc && (
            <Badge size="sm" variant="outline" color={color}>
              {node.cdc}
            </Badge>
          )}
          {meaning && (
            <Text size="xs" c="dimmed" fs="italic" style={{ whiteSpace: "nowrap" }}>
              — {meaning}
            </Text>
          )}
        </Group>
      </UnstyledButton>
      {open &&
        node.children.map((c) => (
          <AttrRow key={c.id} node={c} values={values} depth={depth + 1} picked={picked} onPick={onPick} />
        ))}
    </Box>
  );
}

export function DetailPanel({
  node,
  values,
  picked,
  onPick,
}: {
  node: TreeNode;
  values: Map<string, string>;
  picked: string | null;
  onPick: (node: TreeNode) => void;
}) {
  const kids = node.children;
  if (kids.length === 0) {
    return <AttrRow node={node} values={values} depth={0} picked={picked} onPick={onPick} />;
  }
  return (
    <Box>
      {kids.map((c) => (
        <AttrRow key={c.id} node={c} values={values} depth={0} picked={picked} onPick={onPick} />
      ))}
    </Box>
  );
}
