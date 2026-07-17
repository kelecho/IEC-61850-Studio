import React from "react";
import ReactDOM from "react-dom/client";
import { createTheme, MantineProvider, type MantineColorsTuple } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import "@mantine/core/styles.css";
import "@mantine/notifications/styles.css";
import "@fontsource-variable/ibm-plex-sans";
import "@fontsource-variable/jetbrains-mono";
import App from "./App";
import "./styles.css";

// Paleta oscura "acero" (azul frío, profunda): el fondo de un panel de
// instrumentación, no el gris genérico de Mantine.
const dark: MantineColorsTuple = [
  "#C9D1DC",
  "#A8B2C0",
  "#8793A4",
  "#67748A",
  "#495365",
  "#333C4C",
  "#232B38",
  "#181E28",
  "#10151D",
  "#0B0F15",
];

// Color de marca: cobre de embarrado. El conductor es la identidad del
// dominio (subestaciones); los colores semánticos de calidad (teal/rojo/
// amarillo) quedan libres para su función normativa.
const brand: MantineColorsTuple = [
  "#FBF1E7",
  "#F3DFC9",
  "#E7C29B",
  "#DBA36C",
  "#D18B48",
  "#C9793A",
  "#B96C31",
  "#9E5B2B",
  "#824B25",
  "#673C1F",
];

const theme = createTheme({
  fontFamily: "'IBM Plex Sans Variable', system-ui, -apple-system, sans-serif",
  fontFamilyMonospace: "'JetBrains Mono Variable', ui-monospace, monospace",
  headings: {
    fontFamily: "'IBM Plex Sans Variable', system-ui, sans-serif",
    fontWeight: "650",
  },
  primaryColor: "brand",
  primaryShade: { light: 7, dark: 5 },
  // El cobre es claro: los rellenos deciden texto oscuro/claro por luminancia
  // (como un LED ámbar serigrafiado en negro).
  autoContrast: true,
  luminanceThreshold: 0.42,
  defaultRadius: "sm",
  cursorType: "pointer",
  colors: { dark, brand },
  // Tamaños de fuente (xs 13 · sm 15 · md 17 · lg 19 · xl 21 px).
  fontSizes: {
    xs: "0.8125rem",
    sm: "0.9375rem",
    md: "1.0625rem",
    lg: "1.1875rem",
    xl: "1.3125rem",
  },
  // Densidad equilibrada: cabeceras/tarjetas con aire (vía spacing), tablas
  // compactas (vía defaults del componente Table).
  components: {
    Table: {
      defaultProps: {
        verticalSpacing: 6,
        horizontalSpacing: "md",
        highlightOnHover: true,
        fontSize: "xs",
      },
    },
    Paper: { defaultProps: { radius: "sm" } },
    Card: { defaultProps: { radius: "sm" } },
    Tooltip: { defaultProps: { openDelay: 250, withArrow: true } },
    Button: { defaultProps: { radius: "sm" } },
    Badge: { defaultProps: { radius: "xs" } },
  },
});

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <MantineProvider theme={theme} defaultColorScheme="dark">
      <Notifications position="top-right" />
      <App />
    </MantineProvider>
  </React.StrictMode>,
);
