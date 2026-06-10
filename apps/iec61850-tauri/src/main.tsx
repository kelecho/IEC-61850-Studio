import React from "react";
import ReactDOM from "react-dom/client";
import { createTheme, MantineProvider, type MantineColorsTuple } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import "@mantine/core/styles.css";
import "@mantine/notifications/styles.css";
import "@fontsource-variable/montserrat";
import "@fontsource-variable/jetbrains-mono";
import App from "./App";
import "./styles.css";

// Paleta oscura propia (azul-pizarra), distinta del gris por defecto de Mantine.
const dark: MantineColorsTuple = [
  "#c7d0e0",
  "#aab5c8",
  "#8a97ad",
  "#67748c",
  "#48536a",
  "#343e54",
  "#283044",
  "#1d2436",
  "#151b2a",
  "#0e131f",
];

const theme = createTheme({
  fontFamily: "'Montserrat Variable', system-ui, -apple-system, sans-serif",
  fontFamilyMonospace: "'JetBrains Mono Variable', ui-monospace, monospace",
  headings: { fontFamily: "'Montserrat Variable', system-ui, sans-serif" },
  primaryColor: "indigo",
  defaultRadius: "md",
  colors: { dark },
  // Tamaños de fuente (xs 13 · sm 15 · md 17 · lg 19 · xl 21 px).
  fontSizes: {
    xs: "0.8125rem",
    sm: "0.9375rem",
    md: "1.0625rem",
    lg: "1.1875rem",
    xl: "1.3125rem",
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
