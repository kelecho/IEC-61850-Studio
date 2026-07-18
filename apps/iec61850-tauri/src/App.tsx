import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open, save } from "@tauri-apps/plugin-dialog";
import {
  Accordion,
  ActionIcon,
  Badge,
  Box,
  Button,
  Card,
  Checkbox,
  Code,
  Divider,
  Group,
  Indicator,
  Modal,
  NumberInput,
  Paper,
  Popover,
  ScrollArea,
  SegmentedControl,
  Select,
  SimpleGrid,
  Stack,
  Switch,
  Table,
  Tabs,
  Text,
  TextInput,
  Title,
  Tooltip,
  useComputedColorScheme,
  useMantineColorScheme,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { Panel, PanelGroup, PanelResizeHandle } from "react-resizable-panels";
import {
  IconBroadcast,
  IconChevronDown,
  IconChevronUp,
  IconDatabase,
  IconDownload,
  IconEye,
  IconFileImport,
  IconFlask2,
  IconFolder,
  IconFolderOpen,
  IconGitCompare,
  IconHandClick,
  IconLayoutDashboard,
  IconAlertTriangle,
  IconLock,
  IconShieldCheck,
  IconShieldLock,
  IconMoon,
  IconNetwork,
  IconRss,
  IconPlayerPlay,
  IconPlayerStop,
  IconPlugConnected,
  IconRefresh,
  IconScan,
  IconSearch,
  IconSun,
  IconPlugConnectedX,
  IconTrash,
  IconWaveSine,
} from "@tabler/icons-react";
import { TreeView } from "./components/TreeView";
import { OperBoard, cardFromDrag, type BoardCard, type DragPayload } from "./components/OperBoard";
import { DetailPanel } from "./components/DetailPanel";
import { cdcDesc, doDesc, lnClassOf, lnDesc } from "./iec61850";
import {
  buildTree,
  collectLeafRefs,
  filterTree,
  findQT,
  type DomainItems,
  type TreeNode,
} from "./model";

type Detail = {
  ref: string;
  value: string;
  quality: string | null;
  validity: string | null;
  good: boolean | null;
  time: number | null;
  clockFailure: boolean | null;
  clockNotSynced: boolean | null;
};

// Color por validez tipada (IEC 61850-7-3) + bandera "good".
function validityColor(validity: string | null, good: boolean | null): string {
  if (good) return "teal";
  switch (validity) {
    case "good":
      return "teal";
    case "invalid":
      return "red";
    case "questionable":
      return "yellow";
    case "reserved":
      return "gray";
    default:
      return "gray";
  }
}
function fmtTime(sec: number): string {
  const d = new Date(sec * 1000);
  const ms = Math.round((sec % 1) * 1000)
    .toString()
    .padStart(3, "0");
  return `${d.toLocaleString()}.${ms}`;
}

// Canales del perfil 9-2LE y sus colores (para la gráfica SV).
const SV_CH = ["IA", "IB", "IC", "IN", "VA", "VB", "VC", "VN"];
const SV_COLORS = [
  "#e03131",
  "#2f9e44",
  "#1971c2",
  "#f08c00",
  "#ae3ec9",
  "#0c8599",
  "#5f3dc4",
  "#adb5bd",
];
const SV_WINDOW = 240; // muestras visibles

/// Forma de onda en vivo de los canales SV (canvas propio, sin librerías).
function Waveform({ series, show }: { series: number[][]; show: boolean[] }) {
  const ref = useRef<HTMLCanvasElement | null>(null);
  useEffect(() => {
    const c = ref.current;
    const ctx = c?.getContext("2d");
    if (!c || !ctx) return;
    const W = c.width;
    const H = c.height;
    ctx.clearRect(0, 0, W, H);

    // Retícula de osciloscopio (4 divisiones verticales, 8 horizontales).
    ctx.strokeStyle = "rgba(128,128,128,0.12)";
    ctx.lineWidth = 1;
    ctx.beginPath();
    for (let i = 1; i < 4; i++) {
      const gy = (i / 4) * H;
      ctx.moveTo(0, gy);
      ctx.lineTo(W, gy);
    }
    for (let i = 1; i < 8; i++) {
      const gx = (i / 8) * W;
      ctx.moveTo(gx, 0);
      ctx.lineTo(gx, H);
    }
    ctx.stroke();

    let min = Infinity;
    let max = -Infinity;
    let len = 0;
    for (let ch = 0; ch < series.length; ch++) {
      if (!show[ch]) continue;
      len = Math.max(len, series[ch].length);
      for (const v of series[ch]) {
        if (v < min) min = v;
        if (v > max) max = v;
      }
    }
    if (!isFinite(min)) {
      min = -1;
      max = 1;
    }
    if (min === max) {
      min -= 1;
      max += 1;
    }
    const x = (i: number) => (len <= 1 ? 0 : (i / (len - 1)) * (W - 2) + 1);
    const y = (v: number) => H - 1 - ((v - min) / (max - min)) * (H - 2);

    // línea de cero
    ctx.strokeStyle = "rgba(128,128,128,0.35)";
    ctx.lineWidth = 1;
    ctx.beginPath();
    const zy = y(0);
    ctx.moveTo(0, zy);
    ctx.lineTo(W, zy);
    ctx.stroke();

    for (let ch = 0; ch < series.length; ch++) {
      if (!show[ch] || series[ch].length === 0) continue;
      ctx.strokeStyle = SV_COLORS[ch];
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      series[ch].forEach((v, i) => {
        const X = x(i);
        const Y = y(v);
        if (i === 0) ctx.moveTo(X, Y);
        else ctx.lineTo(X, Y);
      });
      ctx.stroke();
    }
  }, [series, show]);

  return (
    <canvas
      ref={ref}
      width={900}
      height={260}
      style={{
        width: "100%",
        height: 260,
        background: "var(--mantine-color-body)",
        border: "1px solid var(--mantine-color-default-border)",
        borderRadius: 4,
      }}
    />
  );
}

type ConnInfo = { id: string; tls: boolean; active: boolean };
type FoundIed = { addr: string; vendor: string | null; model: string | null; revision: string | null };
type PubInfo = { kind: string; id: string; label: string; dat_set: string; appid: number; src: string; conf_rev: number; count: number };
type FileEntryP = { name: string; size: number; last_modified: string | null };
type ReportEntry = { index: number; value: string };
type ReportRow = {
  n: number;
  t: string;
  source: string;
  rpt_id: string;
  seq_num: number | null;
  entry_id: string | null;
  entries: ReportEntry[];
};
type Pending = {
  title: string;
  body: string;
  run: () => Promise<void>;
  /** Acción de mando sobre un IED real: exige teclear la palabra de confirmación. */
  danger?: boolean;
  /** Aparato/objeto en lenguaje legible, para la cabecera del diálogo. */
  device?: string;
};
type Sort<K extends string> = { key: K; dir: 1 | -1 };

// Acumuladores de estadísticas por stream (en un ref, no provocan render).
type GAcc = { count: number; last: number; gaps: number[]; stChg: number; retx: number; lost: number; stNum: number; sqNum: number };
type SAcc = { count: number; last: number; gaps: number[]; lost: number; smpCnt: number };
type GStat = { key: string; rate: number; jitter: number; stChg: number; retx: number; lost: number; stNum: number; sqNum: number };
type SStat = { key: string; rate: number; jitter: number; count: number; lost: number; smpCnt: number };

function StatCard({ title, value }: { title: string; value: ReactNode }) {
  return (
    <Card withBorder padding="md" radius="md" className="lift">
      <Text size="xs" c="dimmed" tt="uppercase" fw={600} style={{ letterSpacing: 0.4 }}>
        {title}
      </Text>
      <Text size="xl" fw={700} truncate style={{ lineHeight: 1.2, marginTop: 4 }}>
        {value}
      </Text>
    </Card>
  );
}

/** Metadatos de cada sección: cabecera, rail y la parte de la norma que ejercita. */
const SECTION_META: Record<string, { title: string; desc: string; norm: string; icon: ReactNode }> = {
  resumen: { title: "Resumen", desc: "Vista general del IED y su modelo de datos", norm: "IEC 61850-7-1 · Modelo", icon: <IconLayoutDashboard size={22} /> },
  datos: { title: "Datos", desc: "Navega el modelo y lee atributos con calidad y marca de tiempo", norm: "IEC 61850-8-1 · MMS", icon: <IconDatabase size={22} /> },
  reportes: { title: "Reportes", desc: "Habilita RCBs y observa los InformationReport en vivo", norm: "IEC 61850-8-1 · RCB", icon: <IconBroadcast size={22} /> },
  control: { title: "Control", desc: "Operar y escribir (con confirmación) sobre el IED", norm: "IEC 61850-7-2 · Control", icon: <IconHandClick size={22} /> },
  watch: { title: "Vigilar", desc: "Lista curada de atributos con sondeo periódico", norm: "IEC 61850-8-1 · Sondeo", icon: <IconEye size={22} /> },
  goose: { title: "GOOSE", desc: "Monitor, estadísticas y publicación (con simulación Ed.2)", norm: "IEC 61850-8-1 · GOOSE", icon: <IconRss size={22} /> },
  sv: { title: "Sampled Values", desc: "Monitor 9-2LE con forma de onda y simulación Ed.2", norm: "IEC 61850-9-2LE", icon: <IconWaveSine size={22} /> },
  comparar: { title: "Comparar SCL ↔ online", desc: "Diferencias entre el archivo de ingeniería y el dispositivo", norm: "IEC 61850-6 · SCL", icon: <IconGitCompare size={22} /> },
  ficheros: { title: "Ficheros del IED", desc: "Registros de perturbación, COMTRADE y logs (file transfer MMS)", norm: "IEC 61850-8-1 · Ficheros", icon: <IconFolder size={22} /> },
};

/** Cabecera de sección: eyebrow normativo + título + regla con terminal de cobre. */
function SectionHeading({ activeTab }: { activeTab: string | null }) {
  const meta = (activeTab && SECTION_META[activeTab]) || SECTION_META.resumen;
  return (
    <Group gap="sm" mb="md" wrap="nowrap">
      <Box c="brand" style={{ display: "flex" }}>{meta.icon}</Box>
      <div>
        <span className="section-eyebrow">{meta.norm}</span>
        <Title order={4} style={{ lineHeight: 1.15 }}>
          {meta.title}
        </Title>
        <Text size="xs" c="dimmed">
          {meta.desc}
        </Text>
      </div>
      <div className="section-rule" />
    </Group>
  );
}

function csvCell(s: string): string {
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
function toCsv(headers: string[], rows: string[][]): string {
  return [headers, ...rows].map((r) => r.map(csvCell).join(",")).join("\r\n");
}

function avg(a: number[]): number {
  return a.length ? a.reduce((s, x) => s + x, 0) / a.length : 0;
}
function stddev(a: number[]): number {
  if (a.length < 2) return 0;
  const m = avg(a);
  return Math.sqrt(a.reduce((s, x) => s + (x - m) ** 2, 0) / a.length);
}

type GooseRow = {
  n: number;
  t: string;
  gocb_ref: string;
  go_id: string;
  dat_set: string;
  appid: number;
  src: string;
  st_num: number;
  sq_num: number;
  conf_rev: number;
  test: boolean;
  simulation: boolean;
  ttl: number;
  kind: string;
  lost: number;
  values: string[];
};
type SvRow = {
  n: number;
  t: string;
  sv_id: string;
  appid: number;
  src: string;
  simulation: boolean;
  smp_cnt: number;
  conf_rev: number;
  kind: string;
  lost: number;
  channels: Array<{ value: number; quality: number }> | null;
};

const KINDS = ["Bool", "Int", "Uint", "Float", "Text"];

// Bits de TrgOps y OptFlds (IEC 61850-8-1) → casillas.
const TRG = [
  { bit: 1, label: "dchg" },
  { bit: 2, label: "qchg" },
  { bit: 3, label: "dupd" },
  { bit: 4, label: "integridad" },
  { bit: 5, label: "GI" },
];
const OPT = [
  { bit: 1, label: "seqNum" },
  { bit: 2, label: "timestamp" },
  { bit: 3, label: "reason" },
  { bit: 4, label: "dataSet" },
  { bit: 5, label: "dataRef" },
  { bit: 6, label: "bufOvfl" },
  { bit: 7, label: "entryID" },
  { bit: 8, label: "confRev" },
  { bit: 9, label: "segment" },
];

function setBit(arr: boolean[], i: number, val: boolean, len: number): boolean[] {
  const a = arr.slice();
  while (a.length < len) a.push(false);
  a[i] = val;
  return a;
}
function pad(a: boolean[], n: number): boolean[] {
  const r = a.slice(0, n);
  while (r.length < n) r.push(false);
  return r;
}

type RcbForm = {
  rptId: string;
  confRev: number;
  datSet: string;
  intgPd: number;
  bufTm: number;
  trgOps: boolean[];
  optFlds: boolean[];
};

export default function App() {
  const { setColorScheme } = useMantineColorScheme();
  const scheme = useComputedColorScheme("light");

  const [addr, setAddr] = useState("");
  const [conns, setConns] = useState<ConnInfo[]>([]);
  const connected = conns.length > 0;
  const [status, setStatus] = useState("desconectado");
  const [scanOpen, setScanOpen] = useState(false);
  const [scanBase, setScanBase] = useState("192.168.1");
  const [scanPort, setScanPort] = useState(102);
  const [scanning, setScanning] = useState(false);
  const [scanResults, setScanResults] = useState<FoundIed[]>([]);
  const [scanMode, setScanMode] = useState<"mms" | "l2">("mms");
  const [l2Secs, setL2Secs] = useState(4);
  const [l2Scanning, setL2Scanning] = useState(false);
  const [l2Results, setL2Results] = useState<PubInfo[]>([]);
  const [simAddr, setSimAddr] = useState<string | null>(null);

  // TLS / mTLS (IEC 62351-3).
  const CERT_DIR = "/home/kelecho/apps/iec_61850/apps/iec61850-tauri/test-certs";
  const [tlsOn, setTlsOn] = useState(false);
  const [tlsServerName, setTlsServerName] = useState("iec61850-sim");
  const [tlsCa, setTlsCa] = useState(`${CERT_DIR}/ca.crt.pem`);
  const [tlsCert, setTlsCert] = useState(`${CERT_DIR}/client.crt.pem`);
  const [tlsKey, setTlsKey] = useState(`${CERT_DIR}/client.key.pem`);

  const [domains, setDomains] = useState<DomainItems[]>([]);
  const [query, setQuery] = useState("");
  const [navCat, setNavCat] = useState<"model" | "datasets" | "reports">("model");
  const [activeTab, setActiveTab] = useState<string | null>("datos");
  const [pickedId, setPickedId] = useState<string | null>(null);
  const [dsList, setDsList] = useState<Array<{ domain: string; name: string; count: number }>>([]);
  const [dsView, setDsView] = useState<{
    name: string;
    members: Array<{ index: number; reference: string; fc: string; ty: string | null }>;
  } | null>(null);
  const [treeSource, setTreeSource] = useState<"online" | "scl">("scl");
  const [sclPath, setSclPath] = useState("/home/kelecho/apps/iec_61850/fixtures/icd/simple.icd");
  const [sclTree, setSclTree] = useState<TreeNode[]>([]);
  const [reportMembers, setReportMembers] = useState<string[]>([]);
  const [selRef, setSelRef] = useState<string | null>(null);
  const [selNode, setSelNode] = useState<TreeNode | null>(null);
  const [reads, setReads] = useState<Array<[string, string]>>([]);
  const [values, setValues] = useState<Map<string, string>>(new Map());
  const [detail, setDetail] = useState<Detail | null>(null);
  const [polling, setPolling] = useState(false);
  const [pollMs, setPollMs] = useState(1000);
  const pollRefs = useRef<string[]>([]);
  const [watch, setWatch] = useState<string[]>([]);

  const [rcb, setRcb] = useState("IED1LD0/LLN0.rcb1[RP]");
  const [reports, setReports] = useState<ReportRow[]>([]);
  const reportSeq = useRef(0);
  const [rcbForm, setRcbForm] = useState<RcbForm>({
    rptId: "",
    confRev: 0,
    datSet: "",
    intgPd: 0,
    bufTm: 0,
    trgOps: [],
    optFlds: [],
  });

  const [writeKind, setWriteKind] = useState("Float");
  const [writeVal, setWriteVal] = useState("");
  const [ctrlRef, setCtrlRef] = useState("");
  const [ctrlKind, setCtrlKind] = useState("Bool");
  const [ctrlVal, setCtrlVal] = useState("true");
  const [pending, setPending] = useState<Pending | null>(null);
  // Texto tecleado en el diálogo de maniobra (barrera anti-clic accidental).
  const [confirmText, setConfirmText] = useState("");
  // Modo mando: la app arranca en SOLO LECTURA; escribir/operar/publicar exige
  // armarlo explícitamente. Evita maniobras accidentales en un IED productivo.
  const [commandMode, setCommandMode] = useState(false);
  // El sondeo dejó de refrescar (conexión caída): los valores mostrados están
  // caducados aunque sigan en pantalla.
  const [pollStale, setPollStale] = useState(false);
  // Panel de operación (drag & drop de componentes con valores en vivo).
  const [board, setBoard] = useState<BoardCard[]>([]);
  // IEDs en vivo (servidores MMS desde un SCL del usuario, gestionados en la UI).
  const [simScl, setSimScl] = useState("");
  const [simBind, setSimBind] = useState("0.0.0.0:10102");
  const [liveSims, setLiveSims] = useState<Array<{ addr: string; scl: string }>>([]);

  const [readSort, setReadSort] = useState<Sort<"ref" | "val">>({ key: "ref", dir: 1 });
  const [repSort, setRepSort] = useState<Sort<"n" | "rpt" | "seq">>({ key: "n", dir: -1 });

  // Monitores GOOSE / SV (capa 2).
  const [ifaces, setIfaces] = useState<string[]>([]);
  const [iface, setIface] = useState<string | null>(null);
  const [capturing, setCapturing] = useState(false);
  // Publicar GOOSE/SV con el bit de simulación de Ed.2 (pruebas de esquemas).
  const [pubSim, setPubSim] = useState(false);
  // Modo simulación del suscriptor (LPHD.Sim): solo aceptar tramas SIM.
  const [subSim, setSubSim] = useState(false);
  // Transferencia de ficheros (registros/COMTRADE del IED).
  const [files, setFiles] = useState<FileEntryP[]>([]);
  const [filesLoading, setFilesLoading] = useState(false);
  const [gooseRows, setGooseRows] = useState<GooseRow[]>([]);
  const [svRows, setSvRows] = useState<SvRow[]>([]);
  const [gooseOn, setGooseOn] = useState(false);
  const [svOn, setSvOn] = useState(false);
  const [goosePubOn, setGoosePubOn] = useState(false);
  const [svPubOn, setSvPubOn] = useState(false);
  const monSeq = useRef(0);
  const [svSeries, setSvSeries] = useState<number[][]>(() => Array.from({ length: 8 }, () => []));
  const [svShow, setSvShow] = useState<boolean[]>([true, true, true, true, false, false, false, false]);
  const statsRef = useRef<{ goose: Map<string, GAcc>; sv: Map<string, SAcc> }>({
    goose: new Map(),
    sv: new Map(),
  });
  const [gStats, setGStats] = useState<GStat[]>([]);
  const [sStats, setSStats] = useState<SStat[]>([]);

  // ¿La conexión activa es un IED simulado nuestro (banco de pruebas) o un IED
  // real? Solo se considera simulado si su dirección está en el conjunto de
  // simuladores que hemos arrancado; ante la duda se asume REAL (más estricto).
  const activeConnId = conns.find((c) => c.active)?.id ?? null;
  const simAddrs = useMemo(() => {
    const s = new Set<string>();
    if (simAddr) s.add(simAddr);
    s.add("127.0.0.1:10103"); // sim TLS embebido
    for (const l of liveSims) {
      s.add(l.addr);
      s.add(l.addr.replace(/^0\.0\.0\.0/, "127.0.0.1"));
    }
    return s;
  }, [simAddr, liveSims]);
  const activeIsSim = activeConnId ? simAddrs.has(activeConnId) : false;
  // Las maniobras sobre un IED REAL exigen la barrera reforzada; sobre el
  // simulador basta la confirmación simple.
  const dangerZone = connected && !activeIsSim;

  const tree = useMemo(() => {
    const base = treeSource === "scl" ? sclTree : buildTree(domains);
    return filterTree(base, query);
  }, [treeSource, sclTree, domains, query]);
  // RCBs deducidos del modelo (hojas con FC RP/BR), para la categoría «Reportes».
  const rcbList = useMemo(
    () => collectLeafRefs(tree).filter((r) => /\[(RP|BR)\]$/.test(r)).sort(),
    [tree],
  );
  // Diff modelo configurado (SCL) ↔ modelo online (descubierto).
  const diff = useMemo(() => {
    const onlineSet = new Set(domains.flatMap((d) => d.items));
    const sclRefs = collectLeafRefs(sclTree);
    const sclSet = new Set(sclRefs);
    const onlyScl = sclRefs.filter((r) => !onlineSet.has(r)).sort();
    const onlyOnline = [...onlineSet].filter((r) => !sclSet.has(r)).sort();
    const both = sclRefs.filter((r) => onlineSet.has(r)).length;
    const rows = [
      ...onlyScl.map((ref) => ({ ref, side: "SCL" as const })),
      ...onlyOnline.map((ref) => ({ ref, side: "online" as const })),
    ].sort((a, b) => a.ref.localeCompare(b.ref));
    return { both, onlyScl: onlyScl.length, onlyOnline: onlyOnline.length, rows };
  }, [domains, sclTree]);
  // Resumen del modelo activo (LD/LN/atributos + LN por clase).
  const summary = useMemo(() => {
    let lns = 0;
    const byClass: Record<string, number> = {};
    for (const ld of tree) {
      for (const ln of ld.children) {
        lns++;
        const c = lnClassOf(ln.label) ?? ln.label.replace(/\d+$/, "");
        byClass[c] = (byClass[c] ?? 0) + 1;
      }
    }
    const classes = Object.entries(byClass).sort((a, b) => b[1] - a[1]);
    return { lds: tree.length, lns, attrs: collectLeafRefs(tree).length, classes };
  }, [tree]);
  const sortedReads = useMemo(() => {
    const cmp = (a: [string, string], b: [string, string]) =>
      (readSort.key === "ref" ? a[0].localeCompare(b[0]) : a[1].localeCompare(b[1])) * readSort.dir;
    return [...reads].sort(cmp);
  }, [reads, readSort]);
  const sortedReports = useMemo(() => {
    const cmp = (a: ReportRow, b: ReportRow) => {
      let d = 0;
      if (repSort.key === "n") d = a.n - b.n;
      else if (repSort.key === "seq") d = (a.seq_num ?? 0) - (b.seq_num ?? 0);
      else d = a.rpt_id.localeCompare(b.rpt_id);
      return d * repSort.dir;
    };
    return [...reports].sort(cmp);
  }, [reports, repSort]);

  const ok = (m: string) => notifications.show({ color: "teal", message: m, autoClose: 2500 });
  const fail = (e: unknown) => notifications.show({ color: "red", title: "Error", message: String(e) });
  async function pickInto(setter: (s: string) => void, name: string, extensions: string[]) {
    try {
      const sel = await open({ multiple: false, filters: [{ name, extensions }] });
      if (typeof sel === "string") setter(sel);
    } catch (e) {
      fail(e);
    }
  }
  async function exportCsv(suggested: string, headers: string[], rows: string[][]) {
    if (rows.length === 0) {
      fail("nada que exportar");
      return;
    }
    try {
      const path = await save({ defaultPath: suggested, filters: [{ name: "CSV", extensions: ["csv"] }] });
      if (typeof path !== "string") return;
      await invoke("save_text", { path, content: toCsv(headers, rows) });
      ok(`exportado (${rows.length} filas)`);
    } catch (e) {
      fail(e);
    }
  }

  useEffect(() => {
    const un = listen<Omit<ReportRow, "t" | "n">>("report", (e) => {
      const row: ReportRow = {
        ...e.payload,
        n: reportSeq.current++,
        t: new Date().toLocaleTimeString(),
      };
      setReports((prev) => [row, ...prev].slice(0, 300));
    });
    return () => {
      un.then((f) => f());
    };
  }, []);

  // Monitores de capa 2: listeners + lista de interfaces.
  useEffect(() => {
    const ug = listen<Omit<GooseRow, "t" | "n">>("goose", (e) => {
      const row = { ...e.payload, n: monSeq.current++, t: new Date().toLocaleTimeString() };
      setGooseRows((p) => [row, ...p].slice(0, 300));
      const key = e.payload.gocb_ref || e.payload.go_id;
      const now = performance.now();
      const g = statsRef.current.goose;
      let a = g.get(key);
      if (!a) {
        a = { count: 0, last: now, gaps: [], stChg: 0, retx: 0, lost: 0, stNum: 0, sqNum: 0 };
        g.set(key, a);
      }
      if (a.count > 0) {
        a.gaps.push(now - a.last);
        if (a.gaps.length > 64) a.gaps.shift();
      }
      a.count++;
      a.last = now;
      a.stNum = e.payload.st_num;
      a.sqNum = e.payload.sq_num;
      if (e.payload.kind.startsWith("stChange")) a.stChg++;
      else if (e.payload.kind.startsWith("retx")) a.retx++;
      a.lost += e.payload.lost;
    });
    const us = listen<Omit<SvRow, "t" | "n">>("sv", (e) => {
      const row = { ...e.payload, n: monSeq.current++, t: new Date().toLocaleTimeString() };
      setSvRows((p) => [row, ...p].slice(0, 300));
      const ch = row.channels;
      if (ch) {
        setSvSeries((prev) =>
          prev.map((s, i) => {
            const next = [...s, ch[i]?.value ?? 0];
            if (next.length > SV_WINDOW) next.splice(0, next.length - SV_WINDOW);
            return next;
          }),
        );
      }
      const key = e.payload.sv_id;
      const now = performance.now();
      const sv = statsRef.current.sv;
      let a = sv.get(key);
      if (!a) {
        a = { count: 0, last: now, gaps: [], lost: 0, smpCnt: 0 };
        sv.set(key, a);
      }
      if (a.count > 0) {
        a.gaps.push(now - a.last);
        if (a.gaps.length > 64) a.gaps.shift();
      }
      a.count++;
      a.last = now;
      a.smpCnt = e.payload.smp_cnt;
      a.lost += e.payload.lost;
    });
    invoke<string[]>("list_interfaces")
      .then((list) => {
        setIfaces(list);
        setIface((cur) => cur ?? list.find((i) => i !== "lo") ?? list[0] ?? null);
      })
      .catch(() => {});
    return () => {
      ug.then((f) => f());
      us.then((f) => f());
    };
  }, []);

  // Snapshot de estadísticas GOOSE/SV (tasa, jitter) una vez por segundo.
  useEffect(() => {
    const id = setInterval(() => {
      setGStats(
        Array.from(statsRef.current.goose.entries()).map(([key, a]) => ({
          key,
          rate: a.gaps.length ? 1000 / avg(a.gaps) : 0,
          jitter: stddev(a.gaps),
          stChg: a.stChg,
          retx: a.retx,
          lost: a.lost,
          stNum: a.stNum,
          sqNum: a.sqNum,
        })),
      );
      setSStats(
        Array.from(statsRef.current.sv.entries()).map(([key, a]) => ({
          key,
          rate: a.gaps.length ? 1000 / avg(a.gaps) : 0,
          jitter: stddev(a.gaps),
          count: a.count,
          lost: a.lost,
          smpCnt: a.smpCnt,
        })),
      );
    }, 1000);
    return () => clearInterval(id);
  }, []);

  // IEDs en vivo ya arrancados (si la vista se recarga).
  useEffect(() => {
    refreshLiveSims();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Polling continuo: refresca en vivo la watch-list curada.
  useEffect(() => {
    pollRefs.current = watch;
  }, [watch]);
  useEffect(() => {
    if (!polling || !connected) return;
    let cancelled = false;
    const id = setInterval(async () => {
      const refs = pollRefs.current;
      if (refs.length === 0) return;
      const updated = new Map<string, string>();
      let failures = 0;
      for (const ref of refs) {
        try {
          const v = await invoke<string>("read", { reference: ref });
          if (!cancelled) updated.set(ref, v);
        } catch {
          failures++; // lectura fallida: los valores mostrados quedan caducados
        }
      }
      if (cancelled) return;
      // Si TODAS las lecturas fallan, el sondeo está caído: marca datos caducados.
      setPollStale(refs.length > 0 && updated.size === 0 && failures > 0);
      if (updated.size === 0) return;
      setValues((prev) => {
        const m = new Map(prev);
        updated.forEach((v, k) => m.set(k, v));
        return m;
      });
      setReads((prev) => prev.map(([r, v]) => [r, updated.get(r) ?? v] as [string, string]));
      setDetail((d) => (d && updated.has(d.ref) ? { ...d, value: updated.get(d.ref)! } : d));
    }, Math.max(200, pollMs));
    return () => {
      cancelled = true;
      clearInterval(id);
      setPollStale(false);
    };
  }, [polling, connected, pollMs]);

  // Lista de datasets (desde el SCL cargado) al entrar en esa categoría.
  useEffect(() => {
    if (navCat !== "datasets") return;
    invoke<Array<{ domain: string; name: string; count: number }>>("scl_datasets")
      .then(setDsList)
      .catch(() => setDsList([]));
  }, [navCat, sclTree]);

  async function loadDo(reference: string) {
    try {
      const qt = findQT(domains, reference);
      const r = await invoke<{
        value: string;
        quality: string | null;
        validity: string | null;
        good: boolean | null;
        time_epoch: number | null;
        clock_failure: boolean | null;
        clock_not_synced: boolean | null;
      }>("read_do", { value: reference, q: qt.q ?? null, t: qt.t ?? null });
      setDetail({
        ref: reference,
        value: r.value,
        quality: r.quality,
        validity: r.validity,
        good: r.good,
        time: r.time_epoch,
        clockFailure: r.clock_failure,
        clockNotSynced: r.clock_not_synced,
      });
      setReads((p) =>
        [[reference, r.value] as [string, string], ...p.filter((x) => x[0] !== reference)].slice(0, 200),
      );
      setValues((prev) => new Map(prev).set(reference, r.value));
    } catch (e) {
      fail(e);
    }
  }
  function addWatch(reference: string) {
    setWatch((w) => (w.includes(reference) ? w : [...w, reference]));
    if (connected) loadDo(reference);
  }
  function removeWatch(reference: string) {
    setWatch((w) => w.filter((r) => r !== reference));
  }
  // Selección de un DO en el árbol: lee TODOS sus atributos y abre el panel.
  async function onSelectNode(node: TreeNode) {
    setDsView(null);
    setSelNode(node);
    setPickedId(node.reference ? node.id : null);
    setSelRef(node.reference ?? null);
    if (!connected) return;
    const refs = collectLeafRefs([node]);
    if (refs.length === 0) return;
    try {
      const results = await Promise.all(
        refs.map(async (r) => [r, await invoke<string>("read", { reference: r })] as [string, string]),
      );
      setValues((prev) => {
        const m = new Map(prev);
        results.forEach(([r, v]) => m.set(r, v));
        return m;
      });
    } catch (e) {
      fail(e);
    }
  }
  // Elegir un atributo (DA) dentro del panel: pasa a ser el objetivo de leer/escribir.
  function onPick(node: TreeNode) {
    if (!node.reference) return;
    setPickedId(node.id);
    setSelRef(node.reference);
    loadDo(node.reference);
  }
  function pickRcb(ref: string) {
    setRcb(ref);
    setActiveTab("reportes");
  }
  async function pickDs(d: { domain: string; name: string }) {
    try {
      const members = await invoke<Array<{ index: number; reference: string; fc: string; ty: string | null }>>(
        "scl_dataset",
        { domain: d.domain, name: d.name },
      );
      setSelNode(null);
      setDsView({ name: `${d.domain}/${d.name}`, members });
      setActiveTab("datos");
    } catch (e) {
      fail(e);
    }
  }

  async function refreshConns() {
    try {
      setConns(await invoke<ConnInfo[]>("connections"));
    } catch (e) {
      fail(e);
    }
  }
  // Reinicia la vista (datos por-IED) y descubre el modelo de la conexión activa.
  async function switchView() {
    setReads([]);
    setValues(new Map());
    setDetail(null);
    setSelRef(null);
    setWatch([]);
    setCommandMode(false); // cada IED se re-arma explícitamente (seguridad)
    try {
      setDomains(await invoke<DomainItems[]>("discover"));
    } catch {
      setDomains([]);
    }
  }
  async function closeAndRefresh() {
    const list = await invoke<ConnInfo[]>("connections");
    setConns(list);
    if (list.length > 0) {
      await switchView();
    } else {
      setDomains([]);
      setReads([]);
      setValues(new Map());
      setDetail(null);
      setSelRef(null);
      setWatch([]);
      setStatus("desconectado");
    }
  }
  async function connectTo(target: string) {
    const neg = await invoke<string>("connect", { addr: target });
    setStatus(neg);
    await refreshConns();
    await switchView();
  }
  async function doConnect() {
    try {
      await connectTo(addr);
      ok("conectado");
    } catch (e) {
      fail(e);
    }
  }
  async function doScan() {
    setScanning(true);
    setScanResults([]);
    try {
      const r = await invoke<FoundIed[]>("scan_network", { base: scanBase, port: scanPort });
      setScanResults(r);
      ok(`${r.length} host(s) con el puerto abierto`);
    } catch (e) {
      fail(e);
    }
    setScanning(false);
  }
  async function connectFound(target: string) {
    setScanOpen(false);
    setAddr(target);
    try {
      await connectTo(target);
      ok(`conectado a ${target}`);
    } catch (e) {
      fail(e);
    }
  }
  async function doDiscoverL2() {
    if (!iface) return;
    setL2Scanning(true);
    setL2Results([]);
    try {
      const r = await invoke<PubInfo[]>("discover_l2", { iface, secs: l2Secs });
      setL2Results(r);
      ok(`${r.length} publicador(es) GOOSE/SV`);
    } catch (e) {
      fail(e);
    }
    setL2Scanning(false);
  }
  async function doConnectTls() {
    try {
      const neg = await invoke<string>("connect_tls", {
        addr,
        serverName: tlsServerName,
        ca: tlsCa,
        cert: tlsCert,
        key: tlsKey,
      });
      setStatus(neg);
      await refreshConns();
      await switchView();
      ok("conectado (TLS)");
    } catch (e) {
      fail(e);
    }
  }
  async function startSimTls() {
    try {
      const a = await invoke<string>("sim_start_tls");
      setAddr(a);
      setTlsOn(true);
      ok(`simulador TLS en ${a}`);
    } catch (e) {
      fail(e);
    }
  }
  async function switchTo(id: string) {
    try {
      await invoke("set_active", { id });
      await refreshConns();
      await switchView();
    } catch (e) {
      fail(e);
    }
  }
  async function closeConn(id: string) {
    try {
      await invoke("disconnect_id", { id });
      await closeAndRefresh();
    } catch (e) {
      fail(e);
    }
  }
  async function doDiscover() {
    try {
      setDomains(await invoke<DomainItems[]>("discover"));
      ok("modelo descubierto");
    } catch (e) {
      fail(e);
    }
  }
  async function sclLoad(path?: string) {
    const p = path ?? sclPath;
    if (!p) return;
    try {
      const t = await invoke<TreeNode[]>("scl_load", { path: p });
      setSclTree(t);
      setSclPath(p);
      setTreeSource("scl");
      setActiveTab("datos");
      ok(`SCL cargado: ${p.split(/[\\/]/).pop()}`);
    } catch (e) {
      fail(e);
    }
  }
  // Acción primaria: abrir un archivo SCL real (.cid/.icd/.scd) y mostrar su modelo.
  async function openSclDialog() {
    const path = await open({
      multiple: false,
      filters: [{ name: "Archivos SCL", extensions: ["cid", "icd", "scd", "iid", "ssd", "xml"] }],
    });
    if (typeof path === "string") await sclLoad(path);
  }
  // Mapea las entradas de los reportes a nombres de miembro del dataset (vía SCL).
  async function mapMembers() {
    try {
      const p = await invoke<{ dat_set: string }>("rcb_read", { rcb });
      const domain = rcb.split("/")[0];
      const members = await invoke<Array<{ index: number; reference: string }>>("scl_dataset", {
        domain,
        name: p.dat_set,
      });
      setReportMembers(members.map((m) => m.reference));
      ok(`${members.length} miembros mapeados`);
    } catch (e) {
      fail(e);
    }
  }
  async function doEnable() {
    try {
      await invoke("enable_report", { rcb });
      ok("RCB habilitado");
    } catch (e) {
      fail(e);
    }
  }
  async function doDisable() {
    try {
      await invoke("disable_report", { rcb });
      ok("RCB deshabilitado");
    } catch (e) {
      fail(e);
    }
  }
  async function rcbRead() {
    try {
      const p = await invoke<{
        rpt_id: string;
        conf_rev: number;
        dat_set: string;
        intg_pd: number;
        buf_tm: number;
        trg_ops: boolean[];
        opt_flds: boolean[];
      }>("rcb_read", { rcb });
      setRcbForm({
        rptId: p.rpt_id,
        confRev: p.conf_rev,
        datSet: p.dat_set,
        intgPd: p.intg_pd,
        bufTm: p.buf_tm,
        trgOps: pad(p.trg_ops, 6),
        optFlds: pad(p.opt_flds, 10),
      });
      ok("parámetros leídos");
    } catch (e) {
      fail(e);
    }
  }
  async function rcbApply() {
    try {
      await invoke("rcb_write", {
        rcb,
        datSet: rcbForm.datSet,
        intgPd: rcbForm.intgPd,
        bufTm: rcbForm.bufTm,
        trgOps: rcbForm.trgOps,
        optFlds: rcbForm.optFlds,
      });
      ok("parámetros aplicados");
    } catch (e) {
      fail(e);
    }
  }
  async function doSelect() {
    try {
      const r = await invoke<string>("select", { reference: ctrlRef });
      ok(`select: ${r}`);
    } catch (e) {
      fail(e);
    }
  }
  async function startSim() {
    try {
      const a = await invoke<string>("sim_start", { sclPath: null, bind: null });
      setSimAddr(a);
      if (!connected) setAddr(a.replace(/^0\.0\.0\.0/, "127.0.0.1"));
      ok(`simulador IED en ${a}`);
    } catch (e) {
      fail(e);
    }
  }
  async function refreshLiveSims() {
    try {
      setLiveSims(await invoke<Array<{ addr: string; scl: string }>>("sim_live_list"));
    } catch {
      /* sin cambios */
    }
  }
  async function addLiveSim() {
    try {
      const a = await invoke<string>("sim_live_start", {
        sclPath: simScl.trim(),
        bind: simBind.trim() || "0.0.0.0:10102",
      });
      ok(`IED en vivo en ${a}`);
      if (!connected) setAddr(a.replace(/^0\.0\.0\.0/, "127.0.0.1"));
      await refreshLiveSims();
    } catch (e) {
      fail(e);
    }
  }
  async function stopLiveSim(a: string) {
    try {
      await invoke("sim_live_stop", { addr: a });
      await refreshLiveSims();
    } catch (e) {
      fail(e);
    }
  }
  async function stopSim() {
    try {
      await invoke("sim_stop");
      setSimAddr(null);
      ok("simulador detenido");
    } catch (e) {
      fail(e);
    }
  }
  async function gooseStart() {
    if (!iface) return;
    try {
      await invoke("goose_start", { iface, simMode: subSim });
      setGooseOn(true);
      ok(`monitor GOOSE en ${iface}${subSim ? " (modo Sim)" : ""}`);
    } catch (e) {
      fail(e);
    }
  }
  // Captura todo el tráfico de la interfaz a un PCAP (Wireshark).
  async function doCapturePcap() {
    if (!iface) return;
    const path = await save({ defaultPath: "captura.pcap", filters: [{ name: "PCAP", extensions: ["pcap"] }] });
    if (typeof path !== "string") return;
    setCapturing(true);
    try {
      const n = await invoke<number>("capture_pcap", { iface, path, frames: 1000, secs: 20 });
      ok(`${n} tramas capturadas → ${path}`);
    } catch (e) {
      fail(e);
    } finally {
      setCapturing(false);
    }
  }
  // Lista los ficheros del IED de la conexión activa.
  async function loadFiles() {
    setFilesLoading(true);
    try {
      setFiles(await invoke<FileEntryP[]>("file_directory"));
    } catch (e) {
      fail(e);
    } finally {
      setFilesLoading(false);
    }
  }
  // Descarga un fichero del IED a disco.
  async function downloadIedFile(name: string) {
    const dest = await save({ defaultPath: name });
    if (typeof dest !== "string") return;
    try {
      const n = await invoke<number>("download_file", { name, dest });
      ok(`${n} octetos → ${dest}`);
    } catch (e) {
      fail(e);
    }
  }
  async function gooseStop() {
    try {
      await invoke("goose_stop");
    } catch (e) {
      fail(e);
    }
    setGooseOn(false);
  }
  async function svStart() {
    if (!iface) return;
    try {
      await invoke("sv_start", { iface, simMode: subSim });
      setSvOn(true);
      ok(`monitor SV en ${iface}${subSim ? " (modo Sim)" : ""}`);
    } catch (e) {
      fail(e);
    }
  }
  async function svStop() {
    try {
      await invoke("sv_stop");
    } catch (e) {
      fail(e);
    }
    setSvOn(false);
  }
  async function goosePubStart() {
    if (!iface || !commandMode) return;
    try {
      await invoke("goose_pub_start", { iface, simulation: pubSim });
      setGoosePubOn(true);
      ok(`publicador GOOSE de demo iniciado${pubSim ? " (simulación)" : ""}`);
    } catch (e) {
      fail(e);
    }
  }
  async function goosePubStop() {
    try {
      await invoke("goose_pub_stop");
    } catch (e) {
      fail(e);
    }
    setGoosePubOn(false);
  }
  async function svPubStart() {
    if (!iface || !commandMode) return;
    try {
      await invoke("sv_pub_start", { iface, simulation: pubSim });
      setSvPubOn(true);
      ok(`publicador SV de demo iniciado${pubSim ? " (simulación)" : ""}`);
    } catch (e) {
      fail(e);
    }
  }
  async function svPubStop() {
    try {
      await invoke("sv_pub_stop");
    } catch (e) {
      fail(e);
    }
    setSvPubOn(false);
  }

  function askWrite() {
    if (!selRef || !commandMode) return;
    const reference = selRef;
    const kind = writeKind;
    const value = writeVal;
    setConfirmText("");
    setPending({
      title: "Confirmar escritura",
      device: deviceLabel(reference),
      danger: dangerZone,
      body: `Escribir en\n  ${reference}\nel valor ${value} (${kind})`,
      run: async () => {
        await invoke("write", { reference, kind, value });
        ok("escrito");
        loadDo(reference);
      },
    });
  }
  // --- Panel de operación (drag & drop) ---
  function dropOnBoard(p: DragPayload) {
    const card = cardFromDrag(p);
    setBoard((b) => (b.some((c) => c.key === card.key) ? b : [...b, card]));
    setWatch((w) => Array.from(new Set([...w, ...card.refs])));
    setPolling(true); // el panel es "en vivo": arranca el refresco si no estaba
  }
  function removeCard(key: string) {
    setBoard((b) => {
      const gone = b.find((c) => c.key === key);
      const rest = b.filter((c) => c.key !== key);
      if (gone) {
        const still = new Set(rest.flatMap((c) => c.refs));
        setWatch((w) => w.filter((r) => !gone.refs.includes(r) || still.has(r)));
      }
      return rest;
    });
  }
  function clearBoard() {
    setBoard((b) => {
      const refs = new Set(b.flatMap((c) => c.refs));
      setWatch((w) => w.filter((r) => !refs.has(r)));
      return [];
    });
  }
  function operateFromBoard(coRef: string, value: "true" | "false") {
    if (!commandMode) return;
    setConfirmText("");
    setPending({
      title: "Confirmar maniobra",
      device: deviceLabel(coRef),
      danger: dangerZone,
      body: `Operar (operate) el control\n  ${coRef}\ncon ctlVal ${value} (Bool)`,
      run: async () => {
        await invoke("operate", { reference: coRef, kind: "Bool", value });
        ok("operado");
      },
    });
  }

  function askOperate() {
    if (!commandMode) return;
    const reference = ctrlRef;
    const kind = ctrlKind;
    const value = ctrlVal;
    setConfirmText("");
    setPending({
      title: "Confirmar maniobra",
      device: deviceLabel(reference),
      danger: dangerZone,
      body: `Operar (operate) el control\n  ${reference}\ncon ctlVal ${value} (${kind})`,
      run: async () => {
        await invoke("operate", { reference, kind, value });
        ok("operado");
      },
    });
  }
  // Nombre legible del aparato a partir de la referencia (sin FC): p. ej.
  // "IED1LD0/CSWI1.Pos[CO]" → "IED1LD0 · CSWI1 · Pos".
  function deviceLabel(ref: string): string {
    const noFc = ref.replace(/\[[A-Z]{2}\]$/, "");
    const [ld, rest] = noFc.split("/");
    if (!rest) return noFc;
    const [ln, ...segs] = rest.split(".");
    const meaning = doDesc(segs[segs.length - 1] ?? "") ?? lnDesc(ln);
    const base = [ld, ln, ...segs].join(" · ");
    return meaning ? `${base}  (${meaning})` : base;
  }
  // La palabra que hay que teclear para armar una maniobra sobre un IED real.
  const CONFIRM_WORD = "OPERAR";
  async function confirmPending() {
    const p = pending;
    if (p?.danger && confirmText.trim().toUpperCase() !== CONFIRM_WORD) return;
    setPending(null);
    setConfirmText("");
    if (p) {
      try {
        await p.run();
      } catch (e) {
        fail(e);
      }
    }
  }

  // Cabecera de columna ordenable.
  function Th<K extends string>(label: string, k: K, sort: Sort<K>, set: (s: Sort<K>) => void, w?: number) {
    const active = sort.key === k;
    return (
      <Table.Th
        w={w}
        style={{ cursor: "pointer", userSelect: "none" }}
        onClick={() => set({ key: k, dir: active ? ((-sort.dir) as 1 | -1) : 1 })}
      >
        <Group gap={2} wrap="nowrap">
          {label}
          {active && (sort.dir > 0 ? <IconChevronUp size={12} /> : <IconChevronDown size={12} />)}
        </Group>
      </Table.Th>
    );
  }

  return (
    <>
      <div className="ide-root">
        <div className="ide-commandbar">
          <div className="ide-brand">
            <span className="ide-brand-mark">
              <IconNetwork size={17} />
            </span>
            IEC 61850 Studio
          </div>
          <Divider orientation="vertical" />
          <Button size="xs" variant="light" leftSection={<IconFileImport size={14} />} onClick={openSclDialog}>
            Abrir SCL
          </Button>
          <Divider orientation="vertical" />
          <TextInput
            size="xs"
            w={180}
            value={addr}
            disabled={connected}
            onChange={(e) => setAddr(e.currentTarget.value)}
            placeholder="IED  192.168.1.10:102"
          />
          <ActionIcon size="lg" variant="default" title="Buscar IEDs en la red" onClick={() => setScanOpen(true)}>
            <IconScan size={16} />
          </ActionIcon>
          <Popover width={380} position="bottom-start" withArrow shadow="md">
            <Popover.Target>
              <ActionIcon
                size="lg"
                variant={tlsOn ? "filled" : "default"}
                color={tlsOn ? "teal" : "gray"}
                title="TLS / mTLS (IEC 62351-3)"
              >
                <IconLock size={16} />
              </ActionIcon>
            </Popover.Target>
            <Popover.Dropdown>
              <Stack gap="xs">
                <Group justify="space-between">
                  <Text fw={600} size="sm">
                    TLS / mTLS (IEC 62351-3)
                  </Text>
                  <Switch
                    size="xs"
                    label="Usar TLS"
                    checked={tlsOn}
                    onChange={(e) => setTlsOn(e.currentTarget.checked)}
                  />
                </Group>
                <TextInput size="xs" label="Server name (verificado)" value={tlsServerName} onChange={(e) => setTlsServerName(e.currentTarget.value)} />
                <TextInput
                  size="xs"
                  label="CA (PEM)"
                  value={tlsCa}
                  onChange={(e) => setTlsCa(e.currentTarget.value)}
                  rightSection={
                    <ActionIcon variant="subtle" size="sm" title="Examinar…" onClick={() => pickInto(setTlsCa, "PEM", ["pem", "crt", "cer", "key"])}>
                      <IconFolderOpen size={14} />
                    </ActionIcon>
                  }
                />
                <TextInput
                  size="xs"
                  label="Cert cliente (PEM)"
                  value={tlsCert}
                  onChange={(e) => setTlsCert(e.currentTarget.value)}
                  rightSection={
                    <ActionIcon variant="subtle" size="sm" title="Examinar…" onClick={() => pickInto(setTlsCert, "PEM", ["pem", "crt", "cer", "key"])}>
                      <IconFolderOpen size={14} />
                    </ActionIcon>
                  }
                />
                <TextInput
                  size="xs"
                  label="Clave cliente (PEM)"
                  value={tlsKey}
                  onChange={(e) => setTlsKey(e.currentTarget.value)}
                  rightSection={
                    <ActionIcon variant="subtle" size="sm" title="Examinar…" onClick={() => pickInto(setTlsKey, "PEM", ["pem", "crt", "cer", "key"])}>
                      <IconFolderOpen size={14} />
                    </ActionIcon>
                  }
                />
                <Button size="xs" variant="light" color="grape" disabled={connected} onClick={startSimTls}>
                  Iniciar sim TLS (demo)
                </Button>
                <Text size="xs" c="dimmed">
                  Demo: arranca el IED TLS embebido y rellena la dirección; activa «Usar TLS» y pulsa «Conectar TLS».
                </Text>
              </Stack>
            </Popover.Dropdown>
          </Popover>
          <Button
            size="xs"
            color={tlsOn ? "teal" : undefined}
            leftSection={tlsOn ? <IconLock size={14} /> : <IconPlugConnected size={14} />}
            onClick={tlsOn ? doConnectTls : doConnect}
          >
            {tlsOn ? "Conectar TLS" : "Conectar"}
          </Button>
          <ActionIcon size="lg" variant="default" onClick={doDiscover} title="Descubrir activo" disabled={!connected}>
            <IconRefresh size={16} />
          </ActionIcon>
          <Group gap={4} wrap="nowrap" style={{ overflowX: "auto", flex: 1 }}>
            {conns.map((cn) => (
              <Button
                key={cn.id}
                size="xs"
                variant={cn.active ? "filled" : "light"}
                color={cn.tls ? "teal" : "blue"}
                leftSection={cn.tls ? <IconLock size={12} /> : undefined}
                rightSection={
                  <IconPlugConnectedX
                    size={13}
                    onClick={(e) => {
                      e.stopPropagation();
                      closeConn(cn.id);
                    }}
                  />
                }
                onClick={() => switchTo(cn.id)}
                title={cn.active ? "activa" : "cambiar a esta conexión"}
              >
                {cn.id}
              </Button>
            ))}
          </Group>
          <Group gap="xs" wrap="nowrap">
            {connected && (
              <Badge color={activeIsSim ? "grape" : "red"} variant={activeIsSim ? "light" : "filled"}>
                {activeIsSim ? "SIMULADOR" : "IED REAL"}
              </Badge>
            )}
            <Badge color={connected ? "teal" : "gray"} variant="light">
              {connected ? status : "desconectado"}
            </Badge>
            <Tooltip
              label={
                commandMode
                  ? "Modo mando ARMADO: se permite escribir y operar. Clic para volver a solo lectura."
                  : "Solo lectura. Clic para armar el modo mando (escribir/operar)."
              }
              position="bottom"
              multiline
              w={240}
            >
              <ActionIcon
                size="lg"
                variant={commandMode ? "filled" : "default"}
                color={commandMode ? "red" : "gray"}
                disabled={!connected}
                onClick={() => setCommandMode((m) => !m)}
                aria-label="Armar/desarmar modo mando"
              >
                {commandMode ? <IconShieldLock size={16} /> : <IconShieldCheck size={16} />}
              </ActionIcon>
            </Tooltip>
            <Popover width={300} position="bottom-end" withArrow shadow="md">
              <Popover.Target>
                <ActionIcon
                  variant={simAddr ? "filled" : "default"}
                  color={simAddr ? "grape" : "gray"}
                  size="lg"
                  title="Entorno de pruebas (simulador sin hardware)"
                >
                  <IconFlask2 size={16} />
                </ActionIcon>
              </Popover.Target>
              <Popover.Dropdown>
                <Stack gap="xs">
                  <Text fw={600} size="sm">
                    Entorno de pruebas
                  </Text>
                  <Text size="xs" c="dimmed">
                    Sirve cualquier SCL como IED MMS real desde la propia app —
                    visible en la red si escuchas en 0.0.0.0. Puedes arrancar varios
                    (banco de subestación), cada uno en su puerto.
                  </Text>
                  {liveSims.length > 0 && (
                    <Stack gap={4}>
                      {liveSims.map((s) => (
                        <Group key={s.addr} gap={6} wrap="nowrap" justify="space-between">
                          <Text size="xs" ff="monospace" style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis" }}>
                            {s.addr} · {s.scl.split("/").pop()}
                          </Text>
                          <ActionIcon size="sm" variant="subtle" color="red" title="Detener"
                            onClick={() => stopLiveSim(s.addr)}>
                            <IconPlayerStop size={14} />
                          </ActionIcon>
                        </Group>
                      ))}
                    </Stack>
                  )}
                  <Group gap={4} wrap="nowrap">
                    <TextInput
                      size="xs"
                      style={{ flex: 1 }}
                      placeholder="SCL a servir (.cid/.icd/.scd)"
                      value={simScl}
                      onChange={(e) => setSimScl(e.currentTarget.value)}
                    />
                    <ActionIcon variant="default" size="input-xs" title="Examinar…"
                      onClick={() => pickInto(setSimScl, "SCL", ["icd", "cid", "scd", "xml"])}>
                      <IconFolderOpen size={14} />
                    </ActionIcon>
                  </Group>
                  <TextInput
                    size="xs"
                    label="Escucha en"
                    description="0.0.0.0 = visible en la red; 127.0.0.1 = solo local"
                    value={simBind}
                    onChange={(e) => setSimBind(e.currentTarget.value)}
                  />
                  <Button size="xs" variant="light" color="grape" leftSection={<IconPlayerPlay size={14} />}
                    disabled={!simScl.trim()} onClick={addLiveSim}>
                    Iniciar IED en vivo
                  </Button>
                  {simAddr ? (
                    <Button size="xs" variant="light" color="red" leftSection={<IconPlayerStop size={14} />} onClick={stopSim}>
                      Detener simulador de ejemplo ({simAddr})
                    </Button>
                  ) : (
                    <Button size="xs" variant="subtle" color="gray" leftSection={<IconPlayerPlay size={14} />} onClick={startSim}>
                      Simulador de ejemplo (sin SCL)
                    </Button>
                  )}
                </Stack>
              </Popover.Dropdown>
            </Popover>
            <ActionIcon
              variant="default"
              size="lg"
              title="Tema claro/oscuro"
              onClick={() => setColorScheme(scheme === "dark" ? "light" : "dark")}
            >
              {scheme === "dark" ? <IconSun size={16} /> : <IconMoon size={16} />}
            </ActionIcon>
          </Group>
        </div>
        {commandMode && (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              padding: "4px 12px",
              fontSize: "0.8rem",
              fontWeight: 600,
              color: "#fff",
              background: dangerZone
                ? "var(--mantine-color-red-7)"
                : "var(--mantine-color-grape-7)",
            }}
          >
            <IconShieldLock size={15} />
            {dangerZone
              ? `MODO MANDO ARMADO — IED REAL (${activeConnId}). Escribir y operar están habilitados.`
              : `Modo mando armado — simulador (${activeConnId}).`}
            <Button
              size="compact-xs"
              variant="white"
              color="dark"
              ml="auto"
              onClick={() => setCommandMode(false)}
            >
              Volver a solo lectura
            </Button>
          </div>
        )}
        <div className="ide-body">
          <nav className="ide-rail">
            {[
              { v: "resumen", label: "Resumen", icon: <IconLayoutDashboard size={20} />, n: 0 },
              { v: "datos", label: "Datos", icon: <IconDatabase size={20} />, n: 0 },
              { v: "reportes", label: "Reportes", icon: <IconBroadcast size={20} />, n: reports.length },
              { v: "control", label: "Control", icon: <IconHandClick size={20} />, n: 0 },
              { v: "watch", label: "Vigilar", icon: <IconEye size={20} />, n: watch.length },
              { v: "goose", label: "GOOSE", icon: <IconRss size={20} />, n: gooseRows.length },
              { v: "sv", label: "Sampled Values", icon: <IconWaveSine size={20} />, n: svRows.length },
              { v: "comparar", label: "Comparar SCL↔online", icon: <IconGitCompare size={20} />, n: 0 },
              { v: "ficheros", label: "Ficheros del IED", icon: <IconFolder size={20} />, n: files.length },
            ].map((s) => (
              <Tooltip key={s.v} label={s.label} position="right">
                <ActionIcon
                  className="ide-rail-btn"
                  size="xl"
                  radius="md"
                  variant={activeTab === s.v ? "filled" : "subtle"}
                  color={activeTab === s.v ? "brand" : "gray"}
                  data-active={activeTab === s.v || undefined}
                  onClick={() => setActiveTab(s.v)}
                >
                  {s.n ? (
                    <Indicator label={s.n} size={15} color="brand" offset={4}>
                      {s.icon}
                    </Indicator>
                  ) : (
                    s.icon
                  )}
                </ActionIcon>
              </Tooltip>
            ))}
          </nav>
          <PanelGroup direction="horizontal" autoSaveId="ide-layout" style={{ flex: 1, minHeight: 0 }}>
            <Panel id="nav" defaultSize={26} minSize={14} maxSize={48}>
              <div className="ide-nav">
                <Stack gap={6} h="100%">
          <SegmentedControl
            size="xs"
            fullWidth
            value={navCat}
            onChange={(v) => setNavCat(v as "model" | "datasets" | "reports")}
            data={[
              { label: "Modelo", value: "model" },
              { label: "Datasets", value: "datasets" },
              { label: "Reportes", value: "reports" },
            ]}
          />

          {navCat === "model" && (
            <>
              <SegmentedControl
                size="xs"
                fullWidth
                value={treeSource}
                onChange={(v) => setTreeSource(v as "online" | "scl")}
                data={[
                  { label: "Online", value: "online" },
                  { label: "SCL", value: "scl" },
                ]}
              />
              {treeSource === "scl" && (
                <Group gap={4} wrap="nowrap">
                  <TextInput
                    size="xs"
                    style={{ flex: 1 }}
                    placeholder="ruta .scd/.icd/.cid"
                    value={sclPath}
                    onChange={(e) => setSclPath(e.currentTarget.value)}
                  />
                  <ActionIcon variant="default" size="lg" title="Examinar…" onClick={() => pickInto(setSclPath, "SCL", ["icd", "cid", "scd", "xml"])}>
                    <IconFolderOpen size={16} />
                  </ActionIcon>
                  <ActionIcon variant="default" size="lg" onClick={() => sclLoad()} title="Cargar SCL">
                    <IconFileImport size={16} />
                  </ActionIcon>
                </Group>
              )}
              <TextInput
                size="xs"
                placeholder="Buscar…"
                leftSection={<IconSearch size={14} />}
                value={query}
                onChange={(e) => setQuery(e.currentTarget.value)}
              />
              <Box style={{ flex: 1, minHeight: 0 }}>
                <TreeView
                  key={query !== "" ? "f" : "n"}
                  data={tree}
                  selected={selNode?.id ?? null}
                  values={values}
                  forceOpen={query !== ""}
                  maxDepth={2}
                  onSelect={onSelectNode}
                />
              </Box>
            </>
          )}

          {navCat === "reports" && (
            <ScrollArea style={{ flex: 1 }}>
              <Stack gap={2}>
                {rcbList.length === 0 ? (
                  <Text c="dimmed" size="sm">
                    Sin RCBs (conéctate y descubre).
                  </Text>
                ) : (
                  rcbList.map((r) => (
                    <Button key={r} size="xs" variant={rcb === r ? "light" : "subtle"} justify="flex-start" ff="monospace" onClick={() => pickRcb(r)}>
                      {r}
                    </Button>
                  ))
                )}
              </Stack>
            </ScrollArea>
          )}

          {navCat === "datasets" && (
            <ScrollArea style={{ flex: 1 }}>
              <Stack gap={2}>
                {dsList.length === 0 ? (
                  <Text c="dimmed" size="sm">
                    Carga un SCL (categoría Modelo → SCL) para ver los datasets.
                  </Text>
                ) : (
                  dsList.map((d) => (
                    <Button
                      key={`${d.domain}/${d.name}`}
                      size="xs"
                      variant={dsView?.name === `${d.domain}/${d.name}` ? "light" : "subtle"}
                      justify="flex-start"
                      ff="monospace"
                      onClick={() => pickDs(d)}
                    >
                      {d.domain}/{d.name} ({d.count})
                    </Button>
                  ))
                )}
              </Stack>
            </ScrollArea>
          )}
                </Stack>
              </div>
            </Panel>
            <PanelResizeHandle className="ide-resize" />
            <Panel id="main" minSize={30}>
              <div className="ide-main">
                <SectionHeading activeTab={activeTab} />
                <Tabs value={activeTab} onChange={setActiveTab} keepMounted={false}>

          <Tabs.Panel value="resumen" pt="sm">
            <Stack gap="md">
              <SimpleGrid cols={{ base: 2, sm: 4 }} spacing="sm">
                <StatCard title="IED activo" value={conns.find((c) => c.active)?.id ?? "—"} />
                <StatCard title="Disp. lógicos (LD)" value={summary.lds} />
                <StatCard title="Nodos lógicos (LN)" value={summary.lns} />
                <StatCard title="Atributos" value={summary.attrs} />
              </SimpleGrid>
              <Divider label="Nodos lógicos por clase" labelPosition="left" />
              {summary.classes.length === 0 ? (
                <Text c="dimmed" size="sm">
                  Conéctate (o carga un SCL) para ver el resumen del modelo.
                </Text>
              ) : (
                <ScrollArea h={340}>
                  <Table striped withTableBorder stickyHeader fz="xs">
                    <Table.Thead>
                      <Table.Tr>
                        <Table.Th w={90}>Clase</Table.Th>
                        <Table.Th>Significado</Table.Th>
                        <Table.Th w={50}>Nº</Table.Th>
                      </Table.Tr>
                    </Table.Thead>
                    <Table.Tbody>
                      {summary.classes.map(([c, n]) => (
                        <Table.Tr key={c}>
                          <Table.Td>
                            <Badge variant="light">{c}</Badge>
                          </Table.Td>
                          <Table.Td>
                            {lnDesc(c) ?? (
                              <Text c="dimmed" size="xs">
                                (no estándar)
                              </Text>
                            )}
                          </Table.Td>
                          <Table.Td>{n}</Table.Td>
                        </Table.Tr>
                      ))}
                    </Table.Tbody>
                  </Table>
                </ScrollArea>
              )}
            </Stack>
          </Tabs.Panel>

          <Tabs.Panel value="datos" pt="sm">
            <Stack gap="sm">
              {dsView ? (
                <>
                  <Group>
                    <Text fw={600} size="sm">
                      Dataset
                    </Text>
                    <Code>{dsView.name}</Code>
                    <Badge variant="light">{dsView.members.length} miembros</Badge>
                    <Button size="xs" variant="subtle" color="gray" onClick={() => setDsView(null)}>
                      Cerrar
                    </Button>
                  </Group>
                  <ScrollArea h={420}>
                    <Table striped withTableBorder stickyHeader fz="xs" ff="monospace">
                      <Table.Thead>
                        <Table.Tr>
                          <Table.Th w={40}>#</Table.Th>
                          <Table.Th>Referencia</Table.Th>
                          <Table.Th w={60}>FC</Table.Th>
                          <Table.Th w={120}>Tipo</Table.Th>
                        </Table.Tr>
                      </Table.Thead>
                      <Table.Tbody>
                        {dsView.members.map((m) => (
                          <Table.Tr key={m.index}>
                            <Table.Td>{m.index}</Table.Td>
                            <Table.Td>{m.reference}</Table.Td>
                            <Table.Td>
                              <Badge size="xs" variant="light">
                                {m.fc}
                              </Badge>
                            </Table.Td>
                            <Table.Td>{m.ty ?? ""}</Table.Td>
                          </Table.Tr>
                        ))}
                      </Table.Tbody>
                    </Table>
                  </ScrollArea>
                </>
              ) : selNode ? (
                <>
                  <Group gap="xs">
                    <Code>{selNode.id.replace(/^LD:/, "")}</Code>
                    {(() => {
                      const m = doDesc(selNode.label) ?? cdcDesc(selNode.cdc) ?? lnDesc(selNode.label);
                      return m ? (
                        <Text size="sm" c="dimmed" fs="italic">
                          — {m}
                        </Text>
                      ) : null;
                    })()}
                    <Button size="xs" disabled={!connected} onClick={() => onSelectNode(selNode)}>
                      Releer
                    </Button>
                    <Button
                      size="xs"
                      variant="default"
                      leftSection={<IconEye size={14} />}
                      disabled={!selRef}
                      onClick={() => selRef && addWatch(selRef)}
                    >
                      Vigilar
                    </Button>
                  </Group>

                  {detail && (
                    <Group gap="md">
                      <Text size="sm">
                        Valor: <b>{detail.value}</b>
                      </Text>
                      {detail.quality != null && (
                        <Badge color={validityColor(detail.validity, detail.good)} variant="light">
                          {detail.quality}
                        </Badge>
                      )}
                      {detail.clockFailure && (
                        <Badge color="red" variant="outline">
                          reloj: fallo
                        </Badge>
                      )}
                      {detail.clockNotSynced && (
                        <Badge color="orange" variant="outline">
                          reloj: sin sincronizar
                        </Badge>
                      )}
                      {detail.time != null && (
                        <Text size="xs" c="dimmed">
                          {fmtTime(detail.time)}
                        </Text>
                      )}
                    </Group>
                  )}

                  <Paper withBorder p="xs" radius="md">
                    <DetailPanel node={selNode} values={values} picked={pickedId} onPick={onPick} />
                  </Paper>

                  <Group align="end" gap="xs">
                    <Select size="xs" w={100} label="Tipo" data={KINDS} value={writeKind} onChange={(v) => setWriteKind(v ?? "Float")} allowDeselect={false} />
                    <TextInput size="xs" w={140} label="Valor" value={writeVal} onChange={(e) => setWriteVal(e.currentTarget.value)} />
                    <Tooltip label="Arma el modo mando (escudo en la cabecera) para escribir" disabled={commandMode} position="top">
                      <Button size="xs" color="orange" disabled={!connected || !selRef || !commandMode} onClick={askWrite}>
                        Escribir…
                      </Button>
                    </Tooltip>
                    <Text size="xs" c="dimmed">
                      en {selRef ? <Code>{selRef}</Code> : "(elige un atributo)"}
                    </Text>
                  </Group>
                </>
              ) : (
                <Text c="dimmed" size="sm">
                  Selecciona un objeto de dato (DO) en el árbol, o un dataset / RCB en las otras categorías.
                </Text>
              )}
              <Group justify="space-between">
                <Divider label="Lecturas" labelPosition="left" style={{ flex: 1 }} />
                <Button
                  size="xs"
                  variant="default"
                  leftSection={<IconDownload size={14} />}
                  onClick={() => exportCsv("lecturas.csv", ["referencia", "valor"], reads.map(([r, v]) => [r, v]))}
                >
                  Exportar CSV
                </Button>
              </Group>
              <ScrollArea h={320}>
                <Table striped withTableBorder stickyHeader fz="xs" ff="monospace">
                  <Table.Thead>
                    <Table.Tr>
                      {Th("Referencia", "ref", readSort, setReadSort)}
                      {Th("Valor", "val", readSort, setReadSort)}
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {sortedReads.map(([r, v], i) => (
                      <Table.Tr key={i}>
                        <Table.Td>{r}</Table.Td>
                        <Table.Td>{v}</Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </ScrollArea>
            </Stack>
          </Tabs.Panel>

          <Tabs.Panel value="reportes" pt="sm">
            <Stack gap="sm">
              <Group align="end" gap="xs">
                <TextInput size="xs" w={260} label="RCB" value={rcb} onChange={(e) => setRcb(e.currentTarget.value)} />
                <Button size="xs" disabled={!connected} onClick={doEnable}>
                  Habilitar
                </Button>
                <Button size="xs" variant="default" disabled={!connected} onClick={doDisable}>
                  Deshabilitar
                </Button>
                <Button size="xs" variant="subtle" color="gray" onClick={() => setReports([])}>
                  Limpiar
                </Button>
                <Button size="xs" variant="default" onClick={mapMembers} title="Mapear índices a nombres de miembro del dataset (SCL)">
                  Nombres (SCL)
                </Button>
                <Button
                  size="xs"
                  variant="default"
                  leftSection={<IconDownload size={14} />}
                  onClick={() =>
                    exportCsv(
                      "reportes.csv",
                      ["hora", "IED", "rptID", "seq", "entryID", "entradas"],
                      reports.map((r) => [
                        r.t,
                        r.source,
                        r.rpt_id,
                        String(r.seq_num ?? ""),
                        r.entry_id ?? "",
                        r.entries.map((e) => `${reportMembers[e.index] ?? `#${e.index}`}=${e.value}`).join(" | "),
                      ]),
                    )
                  }
                >
                  CSV
                </Button>
              </Group>

              <Accordion variant="separated">
                <Accordion.Item value="rcb">
                  <Accordion.Control>Parámetros del RCB</Accordion.Control>
                  <Accordion.Panel>
                    <Group mb="xs">
                      <Button size="xs" variant="default" disabled={!connected} onClick={rcbRead}>
                        Leer parámetros
                      </Button>
                      <Text size="xs" c="dimmed">
                        RptID: {rcbForm.rptId || "—"} · ConfRev: {rcbForm.confRev}
                      </Text>
                    </Group>
                    <Group align="end" gap="xs">
                      <TextInput
                        size="xs"
                        w={200}
                        label="DatSet"
                        value={rcbForm.datSet}
                        onChange={(e) => setRcbForm((f) => ({ ...f, datSet: e.currentTarget.value }))}
                      />
                      <NumberInput
                        size="xs"
                        w={120}
                        label="IntgPd (ms)"
                        min={0}
                        value={rcbForm.intgPd}
                        onChange={(v) => setRcbForm((f) => ({ ...f, intgPd: Number(v) || 0 }))}
                      />
                      <NumberInput
                        size="xs"
                        w={120}
                        label="BufTm (ms)"
                        min={0}
                        value={rcbForm.bufTm}
                        onChange={(v) => setRcbForm((f) => ({ ...f, bufTm: Number(v) || 0 }))}
                      />
                    </Group>
                    <Text size="xs" fw={600} mt="sm" mb={4}>
                      TrgOps (disparadores)
                    </Text>
                    <Group gap="md">
                      {TRG.map(({ bit, label }) => (
                        <Checkbox
                          key={bit}
                          size="xs"
                          label={label}
                          checked={rcbForm.trgOps[bit] ?? false}
                          onChange={(e) =>
                            setRcbForm((f) => ({ ...f, trgOps: setBit(f.trgOps, bit, e.currentTarget.checked, 6) }))
                          }
                        />
                      ))}
                    </Group>
                    <Text size="xs" fw={600} mt="sm" mb={4}>
                      OptFlds (campos opcionales)
                    </Text>
                    <Group gap="md">
                      {OPT.map(({ bit, label }) => (
                        <Checkbox
                          key={bit}
                          size="xs"
                          label={label}
                          checked={rcbForm.optFlds[bit] ?? false}
                          onChange={(e) =>
                            setRcbForm((f) => ({ ...f, optFlds: setBit(f.optFlds, bit, e.currentTarget.checked, 10) }))
                          }
                        />
                      ))}
                    </Group>
                    <Group mt="md">
                      <Button size="xs" color="orange" disabled={!connected} onClick={rcbApply}>
                        Aplicar parámetros
                      </Button>
                      <Text size="xs" c="dimmed">
                        Aplica y luego «Habilitar» para usarlos.
                      </Text>
                    </Group>
                  </Accordion.Panel>
                </Accordion.Item>
              </Accordion>

              <ScrollArea h={360}>
                <Table striped withTableBorder stickyHeader fz="xs" ff="monospace">
                  <Table.Thead>
                    <Table.Tr>
                      {Th("Hora", "n", repSort, setRepSort, 90)}
                      <Table.Th w={120}>IED</Table.Th>
                      {Th("RptID", "rpt", repSort, setRepSort)}
                      {Th("Seq", "seq", repSort, setRepSort, 50)}
                      <Table.Th w={130}>EntryID</Table.Th>
                      <Table.Th>Entradas</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {sortedReports.map((r) => (
                      <Table.Tr key={r.n}>
                        <Table.Td>{r.t}</Table.Td>
                        <Table.Td>{r.source}</Table.Td>
                        <Table.Td>{r.rpt_id}</Table.Td>
                        <Table.Td>{r.seq_num ?? ""}</Table.Td>
                        <Table.Td>{r.entry_id ?? ""}</Table.Td>
                        <Table.Td>
                          {r.entries
                            .map((e) => `${reportMembers[e.index] ?? `#${e.index}`}=${e.value}`)
                            .join(", ")}
                        </Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </ScrollArea>
            </Stack>
          </Tabs.Panel>

          <Tabs.Panel value="control" pt="sm">
            <Stack gap="sm">
              {connected && !commandMode && (
                <Paper withBorder p="xs" radius="md" bg="var(--mantine-color-default-hover)">
                  <Group gap="xs" wrap="nowrap">
                    <IconShieldCheck size={18} color="var(--mantine-color-teal-6)" />
                    <Text size="sm">
                      <b>Solo lectura.</b> Para escribir u operar, arma el modo mando con el escudo
                      de la cabecera. {dangerZone && "Estás conectado a un IED real."}
                    </Text>
                    <Button size="compact-xs" color="red" ml="auto" onClick={() => setCommandMode(true)}>
                      Armar mando
                    </Button>
                  </Group>
                </Paper>
              )}
              <Text size="sm" c="dimmed">
                Arrastra componentes del árbol al panel para verlos y operarlos en vivo. Cada
                maniobra pide confirmación; sobre un IED real, además exige teclear «{CONFIRM_WORD}».
              </Text>
              <OperBoard
                cards={board}
                values={values}
                connected={connected && commandMode}
                onDropPayload={dropOnBoard}
                onRemove={removeCard}
                onClear={clearBoard}
                onOperate={operateFromBoard}
              />
              <Stack gap="sm" maw={520}>
                <TextInput size="xs" label="Objeto de control [CO]" placeholder="selecciona un control en el árbol o escribe su referencia" value={ctrlRef} onChange={(e) => setCtrlRef(e.currentTarget.value)} />
                <Group align="end" gap="xs">
                  <Select size="xs" w={100} label="Tipo" data={KINDS.filter((k) => k !== "Text")} value={ctrlKind} onChange={(v) => setCtrlKind(v ?? "Bool")} allowDeselect={false} />
                  <TextInput size="xs" w={120} label="ctlVal" value={ctrlVal} onChange={(e) => setCtrlVal(e.currentTarget.value)} />
                  <Button size="xs" variant="default" disabled={!connected || !ctrlRef} onClick={doSelect}>
                    Seleccionar
                  </Button>
                  <Tooltip label="Arma el modo mando para operar" disabled={commandMode} position="top">
                    <Button size="xs" color="orange" disabled={!connected || !ctrlRef || !commandMode} onClick={askOperate}>
                      Operar…
                    </Button>
                  </Tooltip>
                </Group>
              </Stack>
            </Stack>
          </Tabs.Panel>

          {/* --- Vigilar (watch-list) --- */}
          <Tabs.Panel value="watch" pt="sm">
            <Stack gap="sm">
              <Group align="end" gap="xs">
                <Switch
                  size="xs"
                  label="Polling"
                  checked={polling}
                  onChange={(e) => setPolling(e.currentTarget.checked)}
                />
                <NumberInput
                  size="xs"
                  w={120}
                  label="cada (ms)"
                  min={200}
                  step={250}
                  value={pollMs}
                  onChange={(v) => setPollMs(Number(v) || 1000)}
                />
                <Button
                  size="xs"
                  variant="subtle"
                  color="gray"
                  disabled={!watch.length}
                  onClick={() => setWatch([])}
                >
                  Vaciar
                </Button>
                <Text size="xs" c="dimmed">
                  {polling ? `actualizando cada ${Math.max(200, pollMs)} ms` : "polling apagado"}
                </Text>
              </Group>
              {watch.length === 0 ? (
                <Text c="dimmed" size="sm">
                  Lista de vigilancia vacía. Selecciona un atributo en el árbol → pestaña Datos →
                  «Vigilar».
                </Text>
              ) : (
                <ScrollArea h={420}>
                  <Table striped withTableBorder stickyHeader fz="xs" ff="monospace">
                    <Table.Thead>
                      <Table.Tr>
                        <Table.Th>Referencia</Table.Th>
                        <Table.Th w={180}>Valor</Table.Th>
                        <Table.Th w={50} />
                      </Table.Tr>
                    </Table.Thead>
                    <Table.Tbody>
                      {watch.map((ref) => (
                        <Table.Tr key={ref}>
                          <Table.Td
                            style={{ cursor: "pointer" }}
                            onClick={() => {
                              setSelRef(ref);
                              if (connected) loadDo(ref);
                            }}
                          >
                            {ref}
                          </Table.Td>
                          <Table.Td c="teal">{values.get(ref) ?? "—"}</Table.Td>
                          <Table.Td>
                            <ActionIcon
                              size="sm"
                              variant="subtle"
                              color="red"
                              title="Quitar"
                              onClick={() => removeWatch(ref)}
                            >
                              <IconTrash size={14} />
                            </ActionIcon>
                          </Table.Td>
                        </Table.Tr>
                      ))}
                    </Table.Tbody>
                  </Table>
                </ScrollArea>
              )}
            </Stack>
          </Tabs.Panel>

          {/* --- GOOSE --- */}
          <Tabs.Panel value="goose" pt="sm">
            <Stack gap="sm">
              <Group align="end" gap="xs">
                <Select size="xs" w={160} label="Interfaz" data={ifaces} value={iface} onChange={setIface} searchable />
                {gooseOn ? (
                  <Button size="xs" color="red" onClick={gooseStop}>
                    Detener
                  </Button>
                ) : (
                  <Button size="xs" disabled={!iface} onClick={gooseStart}>
                    Iniciar
                  </Button>
                )}
                <Switch
                  size="xs"
                  label="Modo Sim (LPHD.Sim)"
                  checked={subSim}
                  onChange={(e) => setSubSim(e.currentTarget.checked)}
                  disabled={gooseOn || svOn}
                />
                <Button
                  size="xs"
                  variant="subtle"
                  color="gray"
                  onClick={() => {
                    setGooseRows([]);
                    statsRef.current.goose.clear();
                    setGStats([]);
                  }}
                >
                  Limpiar
                </Button>
                <Button
                  size="xs"
                  variant="default"
                  leftSection={<IconDownload size={14} />}
                  onClick={() =>
                    exportCsv(
                      "goose.csv",
                      ["hora", "goID", "gocbRef", "appid", "mac", "stNum", "sqNum", "conf", "test", "tipo", "perdidas", "valores"],
                      gooseRows.map((r) => [
                        r.t,
                        r.go_id,
                        r.gocb_ref,
                        `0x${r.appid.toString(16).padStart(4, "0")}`,
                        r.src,
                        String(r.st_num),
                        String(r.sq_num),
                        String(r.conf_rev),
                        r.test ? "1" : "0",
                        r.kind,
                        String(r.lost),
                        r.values.join(" | "),
                      ]),
                    )
                  }
                >
                  CSV
                </Button>
                <Button
                  size="xs"
                  variant="default"
                  color="blue"
                  leftSection={<IconDownload size={14} />}
                  loading={capturing}
                  disabled={!iface}
                  onClick={doCapturePcap}
                >
                  Capturar PCAP
                </Button>
                <Divider orientation="vertical" />
                {goosePubOn ? (
                  <Button size="xs" variant="light" color="red" onClick={goosePubStop}>
                    Detener pub. demo
                  </Button>
                ) : (
                  <Tooltip label="Publicar inyecta tramas en el bus: arma el modo mando" disabled={commandMode} position="top" multiline w={230}>
                    <Button size="xs" variant="light" color="grape" disabled={!iface || !commandMode} onClick={goosePubStart}>
                      Publicar demo
                    </Button>
                  </Tooltip>
                )}
                <Switch
                  size="xs"
                  label="Simulación (Ed.2)"
                  checked={pubSim}
                  onChange={(e) => setPubSim(e.currentTarget.checked)}
                  disabled={goosePubOn || svPubOn}
                />
                <Text size="xs" c="dimmed">
                  capa 2 — requiere CAP_NET_RAW/root
                </Text>
              </Group>
              {gStats.length > 0 && (
                <Paper withBorder p="xs" radius="md">
                  <Text size="xs" fw={600} mb={4}>
                    Estadísticas
                  </Text>
                  <Table fz="xs" ff="monospace">
                    <Table.Thead>
                      <Table.Tr>
                        <Table.Th>gocbRef</Table.Th>
                        <Table.Th w={70}>msg/s</Table.Th>
                        <Table.Th w={90}>jitter</Table.Th>
                        <Table.Th w={60}>stChg</Table.Th>
                        <Table.Th w={60}>retx</Table.Th>
                        <Table.Th w={70}>pérdidas</Table.Th>
                        <Table.Th w={70}>stNum</Table.Th>
                        <Table.Th w={70}>sqNum</Table.Th>
                      </Table.Tr>
                    </Table.Thead>
                    <Table.Tbody>
                      {gStats.map((s) => (
                        <Table.Tr key={s.key}>
                          <Table.Td>{s.key}</Table.Td>
                          <Table.Td>{s.rate.toFixed(1)}</Table.Td>
                          <Table.Td>{s.jitter.toFixed(2)} ms</Table.Td>
                          <Table.Td>{s.stChg}</Table.Td>
                          <Table.Td>{s.retx}</Table.Td>
                          <Table.Td>
                            <Text size="xs" c={s.lost ? "red" : undefined}>
                              {s.lost}
                            </Text>
                          </Table.Td>
                          <Table.Td>{s.stNum}</Table.Td>
                          <Table.Td>{s.sqNum}</Table.Td>
                        </Table.Tr>
                      ))}
                    </Table.Tbody>
                  </Table>
                </Paper>
              )}
              <ScrollArea h={400}>
                <Table striped withTableBorder stickyHeader fz="xs" ff="monospace">
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th w={90}>Hora</Table.Th>
                      <Table.Th>goID</Table.Th>
                      <Table.Th w={70}>APPID</Table.Th>
                      <Table.Th w={130}>MAC</Table.Th>
                      <Table.Th w={60}>stNum</Table.Th>
                      <Table.Th w={60}>sqNum</Table.Th>
                      <Table.Th w={50}>conf</Table.Th>
                      <Table.Th w={50}>test</Table.Th>
                      <Table.Th w={50}>sim</Table.Th>
                      <Table.Th w={100}>tipo</Table.Th>
                      <Table.Th>valores</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {gooseRows.map((r) => (
                      <Table.Tr key={r.n}>
                        <Table.Td>{r.t}</Table.Td>
                        <Table.Td>{r.go_id}</Table.Td>
                        <Table.Td>0x{r.appid.toString(16).padStart(4, "0")}</Table.Td>
                        <Table.Td>{r.src}</Table.Td>
                        <Table.Td>{r.st_num}</Table.Td>
                        <Table.Td>{r.sq_num}</Table.Td>
                        <Table.Td>{r.conf_rev}</Table.Td>
                        <Table.Td>{r.test ? "sí" : ""}</Table.Td>
                        <Table.Td>{r.simulation ? <Badge size="xs" color="grape">SIM</Badge> : ""}</Table.Td>
                        <Table.Td>{r.kind}</Table.Td>
                        <Table.Td>{r.values.join(", ")}</Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </ScrollArea>
            </Stack>
          </Tabs.Panel>

          {/* --- Sampled Values --- */}
          <Tabs.Panel value="sv" pt="sm">
            <Stack gap="sm">
              <Group align="end" gap="xs">
                <Select size="xs" w={160} label="Interfaz" data={ifaces} value={iface} onChange={setIface} searchable />
                {svOn ? (
                  <Button size="xs" color="red" onClick={svStop}>
                    Detener
                  </Button>
                ) : (
                  <Button size="xs" disabled={!iface} onClick={svStart}>
                    Iniciar
                  </Button>
                )}
                <Switch
                  size="xs"
                  label="Modo Sim (LPHD.Sim)"
                  checked={subSim}
                  onChange={(e) => setSubSim(e.currentTarget.checked)}
                  disabled={gooseOn || svOn}
                />
                <Button
                  size="xs"
                  variant="subtle"
                  color="gray"
                  onClick={() => {
                    setSvRows([]);
                    setSvSeries(Array.from({ length: 8 }, () => []));
                    statsRef.current.sv.clear();
                    setSStats([]);
                  }}
                >
                  Limpiar
                </Button>
                <Button
                  size="xs"
                  variant="default"
                  leftSection={<IconDownload size={14} />}
                  onClick={() =>
                    exportCsv(
                      "sv.csv",
                      ["hora", "svID", "appid", "mac", "smpCnt", "conf", "tipo", "perdidas", "canales"],
                      svRows.map((r) => [
                        r.t,
                        r.sv_id,
                        `0x${r.appid.toString(16).padStart(4, "0")}`,
                        r.src,
                        String(r.smp_cnt),
                        String(r.conf_rev),
                        r.kind,
                        String(r.lost),
                        r.channels ? r.channels.map((c) => c.value).join(" ") : "",
                      ]),
                    )
                  }
                >
                  CSV
                </Button>
                <Divider orientation="vertical" />
                {svPubOn ? (
                  <Button size="xs" variant="light" color="red" onClick={svPubStop}>
                    Detener pub. demo
                  </Button>
                ) : (
                  <Tooltip label="Publicar inyecta tramas en el bus: arma el modo mando" disabled={commandMode} position="top" multiline w={230}>
                    <Button size="xs" variant="light" color="grape" disabled={!iface || !commandMode} onClick={svPubStart}>
                      Publicar demo
                    </Button>
                  </Tooltip>
                )}
                <Text size="xs" c="dimmed">
                  capa 2 — requiere CAP_NET_RAW/root
                </Text>
              </Group>

              <Paper withBorder p="xs" radius="md">
                <Waveform series={svSeries} show={svShow} />
                <Group gap="md" mt="xs">
                  {SV_CH.map((label, ch) => (
                    <Checkbox
                      key={ch}
                      size="xs"
                      checked={svShow[ch]}
                      onChange={(e) =>
                        setSvShow((s) => s.map((x, i) => (i === ch ? e.currentTarget.checked : x)))
                      }
                      label={
                        <Group gap={4} wrap="nowrap">
                          <span
                            style={{
                              width: 10,
                              height: 10,
                              borderRadius: 2,
                              background: SV_COLORS[ch],
                              display: "inline-block",
                            }}
                          />
                          {label}
                        </Group>
                      }
                    />
                  ))}
                </Group>
              </Paper>

              {sStats.length > 0 && (
                <Paper withBorder p="xs" radius="md">
                  <Text size="xs" fw={600} mb={4}>
                    Estadísticas
                  </Text>
                  <Table fz="xs" ff="monospace">
                    <Table.Thead>
                      <Table.Tr>
                        <Table.Th>svID</Table.Th>
                        <Table.Th w={70}>smp/s</Table.Th>
                        <Table.Th w={90}>jitter</Table.Th>
                        <Table.Th w={80}>muestras</Table.Th>
                        <Table.Th w={70}>pérdidas</Table.Th>
                        <Table.Th w={70}>smpCnt</Table.Th>
                      </Table.Tr>
                    </Table.Thead>
                    <Table.Tbody>
                      {sStats.map((s) => (
                        <Table.Tr key={s.key}>
                          <Table.Td>{s.key}</Table.Td>
                          <Table.Td>{s.rate.toFixed(1)}</Table.Td>
                          <Table.Td>{s.jitter.toFixed(2)} ms</Table.Td>
                          <Table.Td>{s.count}</Table.Td>
                          <Table.Td>
                            <Text size="xs" c={s.lost ? "red" : undefined}>
                              {s.lost}
                            </Text>
                          </Table.Td>
                          <Table.Td>{s.smpCnt}</Table.Td>
                        </Table.Tr>
                      ))}
                    </Table.Tbody>
                  </Table>
                </Paper>
              )}
              <ScrollArea h={260}>
                <Table striped withTableBorder stickyHeader fz="xs" ff="monospace">
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th w={90}>Hora</Table.Th>
                      <Table.Th>svID</Table.Th>
                      <Table.Th w={70}>APPID</Table.Th>
                      <Table.Th w={130}>MAC</Table.Th>
                      <Table.Th w={70}>smpCnt</Table.Th>
                      <Table.Th w={50}>conf</Table.Th>
                      <Table.Th w={50}>sim</Table.Th>
                      <Table.Th w={90}>tipo</Table.Th>
                      <Table.Th>canales (8)</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {svRows.map((r) => (
                      <Table.Tr key={r.n}>
                        <Table.Td>{r.t}</Table.Td>
                        <Table.Td>{r.sv_id}</Table.Td>
                        <Table.Td>0x{r.appid.toString(16).padStart(4, "0")}</Table.Td>
                        <Table.Td>{r.src}</Table.Td>
                        <Table.Td>{r.smp_cnt}</Table.Td>
                        <Table.Td>{r.conf_rev}</Table.Td>
                        <Table.Td>{r.simulation ? <Badge size="xs" color="grape">SIM</Badge> : ""}</Table.Td>
                        <Table.Td>{r.kind}</Table.Td>
                        <Table.Td>{r.channels ? r.channels.map((c) => c.value).join(", ") : "—"}</Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </ScrollArea>
            </Stack>
          </Tabs.Panel>

          {/* --- Comparar SCL ↔ online --- */}
          <Tabs.Panel value="comparar" pt="sm">
            <Stack gap="sm">
              {sclTree.length === 0 || domains.length === 0 ? (
                <Text c="dimmed" size="sm">
                  Carga un SCL (barra izquierda → SCL) y descubre el modelo online (conéctate) para
                  comparar.
                </Text>
              ) : (
                <>
                  <Group gap="xs">
                    <Badge color="teal" variant="light">
                      coincidentes: {diff.both}
                    </Badge>
                    <Badge color="orange" variant="light">
                      solo SCL: {diff.onlyScl}
                    </Badge>
                    <Badge color="blue" variant="light">
                      solo online: {diff.onlyOnline}
                    </Badge>
                  </Group>
                  <Text size="xs" c="dimmed">
                    «solo SCL» = configurado pero ausente en línea (posible discrepancia). «solo
                    online» = presente en el IED pero no en el SCL (incluye RCB/datasets/control, que
                    el árbol SCL no modela).
                  </Text>
                  <ScrollArea h={420}>
                    <Table striped withTableBorder stickyHeader fz="xs" ff="monospace">
                      <Table.Thead>
                        <Table.Tr>
                          <Table.Th w={90}>Lado</Table.Th>
                          <Table.Th>Referencia</Table.Th>
                        </Table.Tr>
                      </Table.Thead>
                      <Table.Tbody>
                        {diff.rows.map((r, i) => (
                          <Table.Tr key={i}>
                            <Table.Td>
                              <Badge size="xs" variant="light" color={r.side === "SCL" ? "orange" : "blue"}>
                                {r.side}
                              </Badge>
                            </Table.Td>
                            <Table.Td>{r.ref}</Table.Td>
                          </Table.Tr>
                        ))}
                      </Table.Tbody>
                    </Table>
                  </ScrollArea>
                </>
              )}
            </Stack>
          </Tabs.Panel>

          <Tabs.Panel value="ficheros" pt="sm">
            <Stack gap="sm">
              <Group align="end" gap="xs">
                <Button size="xs" disabled={!connected} loading={filesLoading} onClick={loadFiles}>
                  Listar ficheros del IED
                </Button>
                <Text size="xs" c="dimmed">
                  Registros de perturbación, COMTRADE, logs (servicio MMS file transfer).
                </Text>
              </Group>
              {files.length === 0 ? (
                <Text size="sm" c="dimmed">
                  {connected ? "Pulsa «Listar» para ver los ficheros del IED activo." : "Conecta a un IED."}
                </Text>
              ) : (
                <ScrollArea h={420}>
                  <Table striped withTableBorder stickyHeader fz="xs" ff="monospace">
                    <Table.Thead>
                      <Table.Tr>
                        <Table.Th>Nombre</Table.Th>
                        <Table.Th w={110}>Tamaño</Table.Th>
                        <Table.Th w={170}>Modificado</Table.Th>
                        <Table.Th w={120} />
                      </Table.Tr>
                    </Table.Thead>
                    <Table.Tbody>
                      {files.map((f) => (
                        <Table.Tr key={f.name}>
                          <Table.Td>{f.name}</Table.Td>
                          <Table.Td>{f.size.toLocaleString()} B</Table.Td>
                          <Table.Td>{f.last_modified ?? ""}</Table.Td>
                          <Table.Td>
                            <Button
                              size="compact-xs"
                              variant="light"
                              leftSection={<IconDownload size={13} />}
                              onClick={() => downloadIedFile(f.name)}
                            >
                              Descargar
                            </Button>
                          </Table.Td>
                        </Table.Tr>
                      ))}
                    </Table.Tbody>
                  </Table>
                </ScrollArea>
              )}
            </Stack>
          </Tabs.Panel>
        </Tabs>
              </div>
            </Panel>
          </PanelGroup>
        </div>
        <div className="ide-statusbar">
          <span className="status-dot" data-off={!connected || undefined} />
          <span>{connected ? `Conectado a ${activeConnId ?? addr}` : "Sin conexión"}</span>
          {connected && (
            <span style={{ color: activeIsSim ? "var(--mantine-color-grape-5)" : "var(--mantine-color-red-5)", fontWeight: 600 }}>
              {activeIsSim ? "SIMULADOR" : "IED REAL"}
            </span>
          )}
          {connected && (
            <span style={{ color: commandMode ? "var(--mantine-color-red-5)" : "var(--mantine-color-dimmed)", fontWeight: commandMode ? 600 : 400 }}>
              {commandMode ? "MANDO ARMADO" : "solo lectura"}
            </span>
          )}
          <span>Reportes: {reports.length}</span>
          {polling && (
            <span style={{ color: pollStale ? "var(--mantine-color-red-5)" : "var(--mantine-color-teal-6)", fontWeight: pollStale ? 600 : 400 }}>
              {pollStale
                ? `SIN REFRESCAR · datos caducados`
                : `Polling ${Math.max(200, pollMs)}ms · ${watch.length} ref`}
            </span>
          )}
          {simAddr && <span>Simulador: {simAddr}</span>}
          <span style={{ marginLeft: "auto" }}>IEC 61850 Studio</span>
        </div>
      </div>

      <Modal opened={scanOpen} onClose={() => setScanOpen(false)} title="Buscar IEDs / publicadores" size="lg" centered>
        <SegmentedControl
          size="xs"
          fullWidth
          mb="sm"
          value={scanMode}
          onChange={(v) => setScanMode(v as "mms" | "l2")}
          data={[
            { label: "IEDs (MMS, red)", value: "mms" },
            { label: "Publicadores GOOSE/SV (capa 2)", value: "l2" },
          ]}
        />
        {scanMode === "mms" && (
          <>
        <Group align="end" gap="xs">
          <TextInput
            size="xs"
            label="Subred /24 (a.b.c)"
            w={150}
            value={scanBase}
            onChange={(e) => setScanBase(e.currentTarget.value)}
          />
          <NumberInput
            size="xs"
            label="Puerto"
            w={100}
            min={1}
            max={65535}
            value={scanPort}
            onChange={(v) => setScanPort(Number(v) || 102)}
          />
          <Button size="xs" loading={scanning} onClick={doScan}>
            Escanear
          </Button>
          <Text size="xs" c="dimmed">
            Sondea .1–.254 del prefijo e identifica los IEDs por MMS (puerto 102 por defecto).
          </Text>
        </Group>
        <ScrollArea h={320} mt="sm">
          <Table striped withTableBorder stickyHeader fz="xs" ff="monospace">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Dirección</Table.Th>
                <Table.Th>Fabricante</Table.Th>
                <Table.Th>Modelo</Table.Th>
                <Table.Th w={80} />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {scanResults.map((f) => (
                <Table.Tr key={f.addr}>
                  <Table.Td>{f.addr}</Table.Td>
                  <Table.Td>
                    {f.vendor ?? (
                      <Text c="dimmed" size="xs">
                        (no MMS)
                      </Text>
                    )}
                  </Table.Td>
                  <Table.Td>{f.model ?? ""}</Table.Td>
                  <Table.Td>
                    <Button size="xs" variant="light" onClick={() => connectFound(f.addr)}>
                      Conectar
                    </Button>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </ScrollArea>
        {!scanning && scanResults.length === 0 && (
          <Text c="dimmed" size="sm" mt="sm">
            Sin resultados todavía. Indica tu subred y pulsa «Escanear». (Filas «no MMS» = puerto
            abierto pero sin asociación MMS.)
          </Text>
        )}
          </>
        )}
        {scanMode === "l2" && (
          <>
            <Group align="end" gap="xs">
              <Select size="xs" w={160} label="Interfaz" data={ifaces} value={iface} onChange={setIface} searchable />
              <NumberInput
                size="xs"
                w={100}
                label="Segundos"
                min={1}
                max={30}
                value={l2Secs}
                onChange={(v) => setL2Secs(Number(v) || 4)}
              />
              <Button size="xs" loading={l2Scanning} disabled={!iface} onClick={doDiscoverL2}>
                Escuchar
              </Button>
              <Text size="xs" c="dimmed">
                Capa 2 — requiere CAP_NET_RAW/root.
              </Text>
            </Group>
            <ScrollArea h={320} mt="sm">
              <Table striped withTableBorder stickyHeader fz="xs" ff="monospace">
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th w={60}>Tipo</Table.Th>
                    <Table.Th>ID (gocbRef / svID)</Table.Th>
                    <Table.Th>goID</Table.Th>
                    <Table.Th>dataSet</Table.Th>
                    <Table.Th w={70}>APPID</Table.Th>
                    <Table.Th w={130}>MAC origen</Table.Th>
                    <Table.Th w={60}>conf</Table.Th>
                    <Table.Th w={60}>tramas</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {l2Results.map((p) => (
                    <Table.Tr key={`${p.kind}:${p.id}`}>
                      <Table.Td>
                        <Badge size="xs" variant="light" color={p.kind === "GOOSE" ? "blue" : "grape"}>
                          {p.kind}
                        </Badge>
                      </Table.Td>
                      <Table.Td>{p.id}</Table.Td>
                      <Table.Td>{p.label}</Table.Td>
                      <Table.Td>{p.dat_set}</Table.Td>
                      <Table.Td>0x{p.appid.toString(16).padStart(4, "0")}</Table.Td>
                      <Table.Td>{p.src}</Table.Td>
                      <Table.Td>{p.conf_rev}</Table.Td>
                      <Table.Td>{p.count}</Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </ScrollArea>
            {!l2Scanning && l2Results.length === 0 && (
              <Text c="dimmed" size="sm" mt="sm">
                Sin resultados. Elige la interfaz, los segundos a escuchar y pulsa «Escuchar».
                Necesitas un publicador en esa red (o usa «Publicar demo» en las pestañas GOOSE/SV).
              </Text>
            )}
          </>
        )}
      </Modal>

      <Modal
        opened={!!pending}
        onClose={() => {
          setPending(null);
          setConfirmText("");
        }}
        title={
          <Group gap="xs">
            <IconAlertTriangle size={18} color="var(--mantine-color-orange-6)" />
            <Text fw={600}>{pending?.title}</Text>
          </Group>
        }
        centered
      >
        {pending?.device && (
          <Paper withBorder p="xs" radius="md" mb="sm">
            <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
              Aparato
            </Text>
            <Text size="sm" fw={600} ff="monospace">
              {pending.device}
            </Text>
          </Paper>
        )}
        {pending?.danger ? (
          <Badge color="red" variant="light" mb="xs">
            IED REAL · {activeConnId}
          </Badge>
        ) : (
          <Badge color="grape" variant="light" mb="xs">
            Simulador · {activeConnId}
          </Badge>
        )}
        <Text size="sm" style={{ whiteSpace: "pre-wrap" }} ff="monospace">
          {pending?.body}
        </Text>
        {pending?.danger && (
          <TextInput
            mt="md"
            size="sm"
            label={`Maniobra sobre un IED real: teclea ${CONFIRM_WORD} para habilitar`}
            placeholder={CONFIRM_WORD}
            value={confirmText}
            onChange={(e) => setConfirmText(e.currentTarget.value)}
            autoFocus
          />
        )}
        <Group justify="flex-end" mt="md">
          <Button
            variant="default"
            onClick={() => {
              setPending(null);
              setConfirmText("");
            }}
          >
            Cancelar
          </Button>
          <Button
            color={pending?.danger ? "red" : "orange"}
            disabled={pending?.danger && confirmText.trim().toUpperCase() !== CONFIRM_WORD}
            onClick={confirmPending}
          >
            {pending?.danger ? "Ejecutar maniobra" : "Confirmar"}
          </Button>
        </Group>
      </Modal>
    </>
  );
}
