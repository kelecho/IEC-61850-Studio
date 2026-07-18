import { useEffect, useRef, useState } from "react";
import {
  ActionIcon,
  Badge,
  Box,
  Button,
  Card,
  Group,
  SimpleGrid,
  Stack,
  Text,
} from "@mantine/core";
import { IconTrash, IconBolt } from "@tabler/icons-react";
import { DRAG_MIME } from "./TreeView";

/** Carta del panel: un componente arrastrado desde el árbol o el detalle. */
export type BoardCard = {
  key: string;
  label: string;
  /** Referencias hoja vigiladas (stVal, q, t, mag.f…). */
  refs: string[];
  /** Clase de datos común del DO (DPC, SPC, MV…), si se conoce (vista SCL). */
  cdc?: string | null;
  /** Referencia del objeto de control (`LD/LN.DO[CO]`) si el componente es operable. */
  coRef?: string;
};

/** Payload de arrastre (árbol / panel de detalle). */
export type DragPayload = { label: string; id: string; refs: string[]; cdc?: string | null };

/** Deriva la carta desde el payload de arrastre. */
export function cardFromDrag(payload: DragPayload): BoardCard {
  // Objeto de control: alguna hoja `….DO.Oper…[CO]` → `LD/LN.DO[CO]`.
  let coRef: string | undefined;
  for (const r of payload.refs) {
    const m = r.match(/^([^[]*?)\.Oper(?:\.[^[]*)?\[CO\]$/);
    if (m) {
      coRef = `${m[1]}[CO]`;
      break;
    }
  }
  // Vigila las hojas más informativas primero (stVal/mag/q/t), máx. 6.
  const score = (r: string) =>
    r.includes(".stVal[") ? 0 : r.includes(".mag.") ? 1 : r.includes(".q[") ? 2 : r.includes(".t[") ? 3 : 4;
  const refs = [...payload.refs].sort((a, b) => score(a) - score(b)).slice(0, 6);
  return { key: payload.id, label: payload.label, refs, cdc: payload.cdc ?? null, coRef };
}

// --- Decodificación de los formatos crudos del backend ---

/** Parsea el Debug de BitString: "BitString { unused_bits: 3, bytes: [0, 0] }". */
function parseBits(s: string): boolean[] | null {
  const m = s.match(/^BitString \{ unused_bits: (\d+), bytes: \[([^\]]*)\] \}$/);
  if (!m) return null;
  const unused = Number(m[1]);
  const bytes = m[2].trim() === "" ? [] : m[2].split(",").map((x) => Number(x.trim()));
  const bits: boolean[] = [];
  for (const b of bytes) for (let i = 7; i >= 0; i--) bits.push(((b >> i) & 1) === 1);
  return bits.slice(0, Math.max(0, bits.length - unused));
}

/** Calidad IEC 61850-7-3: validez (bits 0-1) + banderas de detalle. */
const Q_FLAGS = [
  "overflow",
  "outOfRange",
  "badReference",
  "oscillatory",
  "failure",
  "oldData",
  "inconsistent",
  "inaccurate",
];
type QDecoded = { validity: string; detail: string[]; good: boolean };
function decodeQuality(bits: boolean[]): QDecoded {
  const validity = bits[0] ? (bits[1] ? "questionable" : "reserved") : bits[1] ? "invalid" : "good";
  const detail: string[] = [];
  Q_FLAGS.forEach((f, i) => {
    if (bits[2 + i]) detail.push(f);
  });
  if (bits[10]) detail.push("substituted");
  if (bits[11]) detail.push("test");
  if (bits[12]) detail.push("operatorBlocked");
  return { validity, detail, good: validity === "good" && detail.length === 0 };
}

/** Parsea "utc:0x…" (4 B segundos + 3 B fracción + 1 B calidad); null si sin sello. */
function parseUtc(s: string): number | null {
  const m = s.match(/^utc:0x([0-9a-fA-F]{16})$/);
  if (!m) return null;
  const secs = parseInt(m[1].slice(0, 8), 16);
  if (secs === 0) return null; // época cero: sin sellar
  const frac = parseInt(m[1].slice(8, 14), 16) / 0x1000000;
  return secs + frac;
}

function fmtTime(sec: number): string {
  const d = new Date(sec * 1000);
  const ms = Math.round((sec % 1) * 1000)
    .toString()
    .padStart(3, "0");
  return `${d.toLocaleTimeString()}.${ms}`;
}

const VALIDITY_COLOR: Record<string, string> = {
  good: "teal",
  invalid: "red",
  questionable: "yellow",
  reserved: "gray",
};

// --- Estado del aparato (estilo IEDScout) ---

type SwitchState = "open" | "closed" | "intermediate" | "bad" | "on" | "off";

const STATE_META: Record<SwitchState, { label: string; color: string }> = {
  open: { label: "ABIERTO", color: "teal" },
  closed: { label: "CERRADO", color: "red" },
  intermediate: { label: "INTERMEDIO", color: "yellow" },
  bad: { label: "ERRÓNEO", color: "red" },
  on: { label: "ON", color: "teal" },
  off: { label: "OFF", color: "gray" },
};

/** Interpreta el stVal crudo según el CDC: Dbpos (DPC/DPS) o booleano (SPC/SPS). */
function stateOf(cdc: string | null | undefined, label: string, raw: string | undefined): SwitchState | null {
  if (raw === undefined) return null;
  const isPos = cdc === "DPC" || cdc === "DPS" || label === "Pos";
  if (raw === "true") return isPos ? "closed" : "on";
  if (raw === "false") return isPos ? "open" : "off";
  // Dbpos: bit-string de 2 bits o entero 0..3 (00 intermedio, 01 abierto, 10 cerrado, 11 erróneo).
  let code: number | null = null;
  const bits = parseBits(raw);
  if (bits && bits.length === 2) code = (bits[0] ? 2 : 0) + (bits[1] ? 1 : 0);
  else if (isPos && /^[0-3]$/.test(raw)) code = Number(raw);
  if (code === null) return null;
  return (["intermediate", "open", "closed", "bad"] as const)[code];
}

/** Símbolo unifilar de seccionador/interruptor según el estado. */
function SwitchGlyph({ state, size = 46 }: { state: SwitchState; size?: number }) {
  const color = `var(--mantine-color-${STATE_META[state].color}-6)`;
  const arm =
    state === "closed" || state === "on" ? (
      <line x1="20" y1="29" x2="20" y2="13" stroke={color} strokeWidth="3" strokeLinecap="round" />
    ) : state === "open" || state === "off" ? (
      <line x1="20" y1="29" x2="31" y2="15" stroke={color} strokeWidth="3" strokeLinecap="round" />
    ) : state === "intermediate" ? (
      <line
        x1="20"
        y1="29"
        x2="27"
        y2="14"
        stroke={color}
        strokeWidth="3"
        strokeLinecap="round"
        strokeDasharray="3 3"
      />
    ) : (
      <>
        <line x1="14" y1="27" x2="26" y2="15" stroke={color} strokeWidth="3" strokeLinecap="round" />
        <line x1="26" y1="27" x2="14" y2="15" stroke={color} strokeWidth="3" strokeLinecap="round" />
      </>
    );
  return (
    <svg width={size} height={size} viewBox="0 0 40 40" aria-label={STATE_META[state].label}>
      <line x1="20" y1="2" x2="20" y2="10" stroke="currentColor" strokeWidth="2" />
      <circle cx="20" cy="12" r="2.4" fill="none" stroke="currentColor" strokeWidth="1.6" />
      <circle cx="20" cy="30" r="2.4" fill="none" stroke="currentColor" strokeWidth="1.6" />
      <line x1="20" y1="32" x2="20" y2="38" stroke="currentColor" strokeWidth="2" />
      {arm}
    </svg>
  );
}

// --- Formateo de valores en filas secundarias ---

/** Decodifica un valor crudo del backend para mostrarlo legible. */
function fmtLive(reference: string, raw: string): { text: string; color?: string } {
  const t = parseUtc(raw);
  if (raw.startsWith("utc:")) return t === null ? { text: "— (sin sello)" } : { text: fmtTime(t) };
  const bits = parseBits(raw);
  if (bits) {
    if (/\.q\[[A-Z]{2}\]$/.test(reference)) {
      const q = decodeQuality(bits);
      return {
        text: q.detail.length ? `${q.validity}+${q.detail.join("+")}` : q.validity,
        color: VALIDITY_COLOR[q.validity],
      };
    }
    return { text: bits.map((b) => (b ? "1" : "0")).join("") };
  }
  return { text: raw };
}

function shortRef(full: string, cardLabel: string): string {
  // `LD/LN.DO.attr[FC]` → parte tras el DO si es posible; si no, tras `LN.`.
  const noFc = full.replace(/\[[A-Z]{2}\]$/, "");
  const i = noFc.indexOf(`.${cardLabel}.`);
  if (i >= 0) return noFc.slice(i + cardLabel.length + 2);
  const dot = noFc.indexOf(".");
  return dot >= 0 ? noFc.slice(dot + 1) : noFc;
}

function ValueRow({ full, label, value }: { full: string; label: string; value?: string }) {
  const prev = useRef<string | undefined>(value);
  const [flash, setFlash] = useState(false);
  useEffect(() => {
    if (value !== undefined && prev.current !== undefined && value !== prev.current) {
      setFlash(true);
      const t = setTimeout(() => setFlash(false), 700);
      prev.current = value;
      return () => clearTimeout(t);
    }
    prev.current = value;
  }, [value]);
  const shown = value !== undefined ? fmtLive(full, value) : null;
  return (
    <Group gap={8} wrap="nowrap" title={full}>
      <Text size="xs" ff="monospace" c="dimmed" style={{ whiteSpace: "nowrap" }}>
        {label}
      </Text>
      <Box
        px={6}
        style={{
          borderRadius: 4,
          transition: "background-color 400ms ease",
          background: flash ? "var(--mantine-color-yellow-light)" : "transparent",
          minWidth: 0,
        }}
      >
        <Text
          size="sm"
          ff="monospace"
          fw={600}
          c={shown ? (shown.color ?? "teal.7") : "dimmed"}
          style={{ wordBreak: "break-all" }}
        >
          {shown?.text ?? "—"}
        </Text>
      </Box>
    </Group>
  );
}

/** Bloque de estado destacado: símbolo + etiqueta + calidad + sello de tiempo. */
function StateBlock({ card, values }: { card: BoardCard; values: Map<string, string> }) {
  const stRef = card.refs.find((r) => /\.stVal\[/.test(r));
  if (!stRef) return null;
  const raw = values.get(stRef);
  const state = stateOf(card.cdc, card.label, raw);

  const qRef = card.refs.find((r) => /\.q\[/.test(r));
  const qRaw = qRef ? values.get(qRef) : undefined;
  const qBits = qRaw ? parseBits(qRaw) : null;
  const q = qBits ? decodeQuality(qBits) : null;

  const tRef = card.refs.find((r) => /\.t\[/.test(r));
  const tRaw = tRef ? values.get(tRef) : undefined;
  const tSec = tRaw ? parseUtc(tRaw) : null;

  // Destello del bloque al cambiar el estado.
  const prev = useRef<string | undefined>(raw);
  const [flash, setFlash] = useState(false);
  useEffect(() => {
    if (raw !== undefined && prev.current !== undefined && raw !== prev.current) {
      setFlash(true);
      const t = setTimeout(() => setFlash(false), 700);
      prev.current = raw;
      return () => clearTimeout(t);
    }
    prev.current = raw;
  }, [raw]);

  if (state === null) {
    // stVal no interpretable como aparato: fila normal (medidas, enteros…).
    return null;
  }
  const meta = STATE_META[state];
  return (
    <Group
      gap="sm"
      wrap="nowrap"
      p={6}
      mb={4}
      style={{
        borderRadius: 6,
        border: "1px solid var(--mantine-color-default-border)",
        transition: "background-color 400ms ease",
        background: flash ? "var(--mantine-color-yellow-light)" : "var(--mantine-color-default-hover)",
      }}
    >
      <SwitchGlyph state={state} />
      <Stack gap={2}>
        <Text fw={800} size="lg" c={`${meta.color}.6`} style={{ lineHeight: 1 }}>
          {meta.label}
        </Text>
        <Group gap={6}>
          {q && (
            <Badge size="sm" variant="light" color={VALIDITY_COLOR[q.validity]}>
              {q.detail.length ? `${q.validity}+${q.detail.join("+")}` : q.validity}
            </Badge>
          )}
          <Text size="xs" c="dimmed" ff="monospace">
            {tSec !== null ? fmtTime(tSec) : "sin sello de tiempo"}
          </Text>
        </Group>
      </Stack>
    </Group>
  );
}

export function OperBoard({
  cards,
  values,
  connected,
  onDropPayload,
  onRemove,
  onClear,
  onOperate,
}: {
  cards: BoardCard[];
  values: Map<string, string>;
  connected: boolean;
  onDropPayload: (p: DragPayload) => void;
  onRemove: (key: string) => void;
  onClear: () => void;
  onOperate: (coRef: string, value: "true" | "false") => void;
}) {
  const [over, setOver] = useState(false);
  return (
    <Box
      onDragOver={(e) => {
        if (e.dataTransfer.types.includes(DRAG_MIME)) {
          e.preventDefault();
          e.dataTransfer.dropEffect = "copy";
          setOver(true);
        }
      }}
      onDragLeave={() => setOver(false)}
      onDrop={(e) => {
        setOver(false);
        const raw = e.dataTransfer.getData(DRAG_MIME);
        if (!raw) return;
        e.preventDefault();
        try {
          onDropPayload(JSON.parse(raw));
        } catch {
          /* payload ajeno: ignorar */
        }
      }}
      style={{
        border: `2px dashed ${over ? "var(--mantine-color-blue-5)" : "var(--mantine-color-default-border)"}`,
        borderRadius: 8,
        padding: 12,
        minHeight: 180,
        background: over ? "var(--mantine-color-blue-light)" : undefined,
        transition: "background-color 150ms ease",
      }}
    >
      {cards.length === 0 ? (
        <Stack align="center" justify="center" mih={150} gap={4}>
          <Text c="dimmed" size="sm">
            Arrastra aquí un componente del árbol (DO, control o atributo)
          </Text>
          <Text c="dimmed" size="xs">
            Verás sus valores en tiempo real; los objetos de control podrán operarse.
          </Text>
        </Stack>
      ) : (
        <>
          <Group justify="flex-end" mb={6}>
            <Button size="compact-xs" variant="subtle" color="gray" onClick={onClear}>
              Vaciar panel
            </Button>
          </Group>
          <SimpleGrid cols={{ base: 1, md: 2, xl: 3 }} spacing="sm">
            {cards.map((c) => {
              const hasState =
                stateOf(c.cdc, c.label, c.refs.find((r) => /\.stVal\[/.test(r)) ? values.get(c.refs.find((r) => /\.stVal\[/.test(r))!) : undefined) !== null;
              // El bloque de estado ya enseña stVal/q/t: no repetirlos en filas.
              const rows = hasState
                ? c.refs.filter((r) => !/\.(stVal|q|t)\[/.test(r))
                : c.refs;
              return (
                <Card key={c.key} withBorder padding="sm" radius="md">
                  <Group justify="space-between" mb={4} wrap="nowrap">
                    <Group gap={6} wrap="nowrap">
                      <Text fw={700} ff="monospace" size="sm">
                        {c.label}
                      </Text>
                      {c.cdc && (
                        <Badge size="sm" variant="outline" color="blue">
                          {c.cdc}
                        </Badge>
                      )}
                      {c.coRef && (
                        <Badge size="sm" variant="light" color="orange" leftSection={<IconBolt size={10} />}>
                          CO
                        </Badge>
                      )}
                    </Group>
                    <ActionIcon size="sm" variant="subtle" color="gray" onClick={() => onRemove(c.key)}>
                      <IconTrash size={14} />
                    </ActionIcon>
                  </Group>
                  <StateBlock card={c} values={values} />
                  <Stack gap={2}>
                    {rows.map((r) => (
                      <ValueRow key={r} full={r} label={shortRef(r, c.label)} value={values.get(r)} />
                    ))}
                  </Stack>
                  {c.coRef && (
                    <Group gap="xs" mt={8}>
                      <Button
                        size="compact-xs"
                        color="red"
                        disabled={!connected}
                        onClick={() => onOperate(c.coRef!, "true")}
                      >
                        Cerrar / ON…
                      </Button>
                      <Button
                        size="compact-xs"
                        color="teal"
                        disabled={!connected}
                        onClick={() => onOperate(c.coRef!, "false")}
                      >
                        Abrir / OFF…
                      </Button>
                    </Group>
                  )}
                </Card>
              );
            })}
          </SimpleGrid>
        </>
      )}
    </Box>
  );
}
