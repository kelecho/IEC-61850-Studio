// Catálogo semántico IEC 61850 (curado esencial): traduce clases de nodo lógico
// (LN, 7-4), clases de datos comunes (CDC, 7-3), restricciones funcionales (FC) y
// nombres de datos comunes a texto legible. Las búsquedas de LN/CDC/FC se
// normalizan en mayúsculas; las de DO/DA respetan el nombre estándar.

export const LN_CLASS: Record<string, string> = {
  LLN0: "Nodo lógico cero (común del LD)",
  LPHD: "Datos físicos del dispositivo",
  // Protección (P)
  PTOC: "Sobreintensidad temporizada",
  PIOC: "Sobreintensidad instantánea",
  PTOV: "Sobretensión",
  PTUV: "Subtensión",
  PTRC: "Acondicionamiento de disparo (trip)",
  PDIS: "Protección de distancia",
  PDIF: "Protección diferencial",
  PTTR: "Imagen térmica",
  PFRC: "Frecuencia (df/dt)",
  PHAR: "Restricción por armónicos",
  PVOC: "Sobreintensidad dependiente de tensión",
  PTEF: "Falta a tierra direccional",
  // Control (C)
  CSWI: "Control de maniobra",
  CILO: "Enclavamiento (interlocking)",
  CALH: "Manejo de alarmas",
  CPOW: "Control de cierre por onda",
  // Aparamenta (X)
  XCBR: "Interruptor automático",
  XSWI: "Seccionador / maniobra",
  // Medida (M)
  MMXU: "Medidas (unidad de medida)",
  MMXN: "Medidas no fásicas",
  MMTR: "Contador / energía",
  MSQI: "Componentes simétricas",
  MHAI: "Armónicos / interarmónicos",
  // Genéricos (G)
  GGIO: "Entradas/salidas genéricas",
  GAPC: "Automatismo genérico",
  // Transformadores de medida (T)
  TCTR: "Transformador de intensidad",
  TVTR: "Transformador de tensión",
  // Supervisión (S)
  SIMG: "Supervisión de gas aislante",
  SARC: "Detección de arco",
  SPDC: "Descargas parciales",
  // Automáticos / relacionados (R)
  RREC: "Reenganchador",
  RBRF: "Fallo de interruptor",
  RSYN: "Comprobación de sincronismo",
  RDIR: "Elemento direccional",
  RFLO: "Localizador de falta",
  RPSB: "Bloqueo por oscilación de potencia",
  // Interfaz (I)
  IHMI: "Interfaz hombre-máquina",
  ITCI: "Telecontrol",
  // Control automático (A)
  ATCC: "Control de tomas (OLTC)",
  AVCO: "Control de tensión",
  // Protección (P) — adicionales
  PDOP: "Sobrepotencia direccional",
  PDUP: "Subpotencia direccional",
  PSCH: "Esquema de teleprotección",
  PSDE: "Falta a tierra sensible direccional",
  PTUC: "Subintensidad",
  PHIZ: "Falta de alta impedancia",
  PMSS: "Supervisión de arranque de motor",
  // Relacionados con protección (R) — adicionales
  RDRE: "Registrador de perturbaciones",
  // Sistema / lógicos (L) — adicionales
  LGOS: "Supervisión de suscripción GOOSE",
  LSVS: "Supervisión de suscripción SV",
  LTIM: "Gestión de hora",
  LTMS: "Supervisión de comunicación",
  LCCH: "Canal de comunicación",
  // Genéricos (G) — adicionales
  GSAL: "Alarmas de seguridad",
  // Medida (M) — adicionales
  MSTA: "Estadísticas de medida",
  // Supervisión (S) — adicionales
  SIML: "Supervisión de líquido aislante",
  // Interfaz / archivo (I) — adicionales
  IARC: "Archivo de registros",
  ITMI: "Telemedida",
  // Funciones genéricas (F)
  FCNT: "Contador",
  FPID: "Regulador PID",
  FFIL: "Filtro",
  FRMP: "Rampa",
  FSPT: "Punto de consigna",
  // Equipos mecánicos / refrigeración (K)
  KPMP: "Bomba",
  KFAN: "Ventilador",
  // Calidad de onda (Q)
  QVVR: "Variación de tensión",
  QITR: "Transitorios de intensidad",
  QVTR: "Transitorios de tensión",
  // Equipos de potencia (Z)
  ZBAT: "Batería",
  ZCAP: "Banco de condensadores",
  ZGEN: "Generador",
  ZLIN: "Línea",
  ZMOT: "Motor",
  ZSAR: "Pararrayos",
  ZREA: "Reactancia",
  ZBSH: "Pasatapas (bushing)",
};

export const CDC: Record<string, string> = {
  // Estado
  SPS: "Estado de punto simple",
  DPS: "Estado de punto doble",
  INS: "Estado entero",
  ENS: "Estado enumerado",
  ACT: "Activación de protección (trip)",
  ACD: "Activación direccional",
  SEC: "Contador de seguridad",
  BCR: "Contador binario",
  // Medidos
  MV: "Valor medido",
  CMV: "Valor medido complejo",
  SAV: "Valor muestreado",
  WYE: "Trifásico en estrella (fase-neutro)",
  DEL: "Trifásico en triángulo (fase-fase)",
  SEQ: "Componentes de secuencia",
  HMV: "Armónicos (magnitud)",
  // Estado controlable
  SPC: "Control de punto simple",
  DPC: "Control de punto doble",
  INC: "Control entero",
  ENC: "Control enumerado",
  BSC: "Control paso a paso",
  ISC: "Control paso entero",
  // Analógico controlable
  APC: "Control analógico (setpoint)",
  BAC: "Control analógico paso a paso",
  // Ajustes
  SPG: "Ajuste de punto simple",
  ING: "Ajuste entero",
  ENG: "Ajuste enumerado",
  ASG: "Ajuste analógico",
  CURVE: "Curva de ajuste",
  // Descripción
  DPL: "Placa de características del dispositivo",
  LPL: "Placa del nodo lógico",
};

export const FC: Record<string, string> = {
  ST: "Estado (status)",
  MX: "Medida (analógica)",
  CO: "Control",
  SP: "Punto de ajuste (setpoint)",
  SG: "Grupo de ajustes",
  SE: "Grupo de ajustes editable",
  CF: "Configuración",
  DC: "Descripción",
  SV: "Sustitución",
  EX: "Extensión",
  BL: "Bloqueo",
  RP: "Reporte no bufferado (control)",
  BR: "Reporte bufferado (control)",
  LG: "Registro (log)",
  GO: "Control GOOSE",
  MS: "Control de muestreo (SV multicast)",
  US: "Control de muestreo (SV unicast)",
};

// Nombres de datos (DO) y atributos (DA) comunes.
export const DO_NAME: Record<string, string> = {
  Mod: "Modo",
  Beh: "Comportamiento",
  Health: "Salud",
  NamPlt: "Placa de características",
  Loc: "Local / Remoto",
  A: "Corriente de fase",
  PhV: "Tensión fase-tierra",
  PPV: "Tensión fase-fase",
  W: "Potencia activa",
  VAr: "Potencia reactiva",
  VA: "Potencia aparente",
  PF: "Factor de potencia",
  Hz: "Frecuencia",
  Pos: "Posición",
  OpCnt: "Contador de operaciones",
  CBOpCap: "Capacidad de maniobra",
  Str: "Arranque (pickup)",
  Op: "Operación (trip)",
  TmASt: "Estado temporización",
  stVal: "Valor de estado",
  q: "Calidad",
  t: "Marca de tiempo",
  cVal: "Valor complejo",
  mag: "Magnitud",
  ang: "Ángulo",
  ctlVal: "Valor de control",
  Oper: "Operar",
  SBOw: "Select-Before-Operate (con valor)",
  Cancel: "Cancelar",
  ctlModel: "Modelo de control",
};

/** Categoría de un CDC (para iconos de DO): medido / estado / control / ajuste / descripción. */
export function cdcCategory(cdc?: string | null): string {
  if (!cdc) return "do";
  const c = cdc.toUpperCase();
  if (["MV", "CMV", "SAV", "WYE", "DEL", "SEQ", "HMV", "HWYE", "HDEL"].includes(c)) return "measured";
  if (["SPS", "DPS", "INS", "ENS", "ACT", "ACD", "SEC", "BCR", "HST", "VSS"].includes(c)) return "status";
  if (["SPC", "DPC", "INC", "ENC", "BSC", "ISC", "APC", "BAC"].includes(c)) return "control";
  if (["SPG", "ING", "ENG", "ASG", "CURVE", "CSG"].includes(c)) return "setting";
  if (["DPL", "LPL", "CSD"].includes(c)) return "description";
  return "do";
}

const up = (s: string) => s.toUpperCase();

/** Extrae la clase de LN (4 letras) del nombre de un LN (prefijo+clase+inst). */
export function lnClassOf(label: string): string | null {
  const u = up(label);
  if (LN_CLASS[u]) return u; // p. ej. LLN0
  const noInst = u.replace(/\d+$/, ""); // quita instancia final
  if (LN_CLASS[noInst]) return noInst;
  const last4 = noInst.slice(-4);
  return LN_CLASS[last4] ? last4 : null;
}

export const lnDesc = (label: string): string | null => {
  const c = lnClassOf(label);
  return c ? LN_CLASS[c] : null;
};
export const cdcDesc = (cdc?: string | null): string | null =>
  cdc ? (CDC[up(cdc)] ?? null) : null;
export const fcDesc = (fc?: string | null): string | null =>
  fc ? (FC[up(fc)] ?? null) : null;
export const doDesc = (name?: string | null): string | null =>
  name ? (DO_NAME[name] ?? null) : null;

/** Categoría de icono según el grupo de LN (primera letra de la clase IEC 7-4). */
export function lnIconKey(label: string): string {
  const c = lnClassOf(label) ?? label.toUpperCase();
  switch (c[0]) {
    case "L":
      return "common"; // LLN0, LPHD
    case "P":
    case "R":
      return "protection"; // protección y relacionados
    case "C":
      return "control";
    case "X":
      return "switch"; // aparamenta
    case "M":
      return "measure";
    case "T":
      return "transformer";
    case "S":
      return "supervision";
    case "G":
      return "io"; // genéricos
    case "I":
      return "interface";
    case "A":
      return "auto";
    case "F":
      return "control"; // bloques de función
    case "K":
      return "switch"; // equipos mecánicos
    case "Q":
      return "measure"; // calidad de onda
    case "Z":
      return "equipment"; // equipos de potencia
    default:
      return "ln";
  }
}

/** Color (Mantine) por grupo de FC, para el árbol/badges. */
export function fcColor(fc?: string | null): string {
  switch (up(fc ?? "")) {
    case "ST":
      return "blue";
    case "MX":
      return "teal";
    case "CO":
      return "orange";
    case "SP":
    case "SG":
    case "SE":
      return "grape";
    case "CF":
    case "DC":
      return "gray";
    case "RP":
    case "BR":
    case "GO":
    case "MS":
    case "US":
      return "indigo";
    default:
      return "gray";
  }
}
