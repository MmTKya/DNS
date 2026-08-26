import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App.tsx";
import { LanguageProvider } from "./i18n/context.tsx";
import "./index.css";

const root = document.getElementById("root");
if (!root) {
  throw new Error("#root is missing from index.html");
}

createRoot(root).render(
  <StrictMode>
    <LanguageProvider>
      <App />
    </LanguageProvider>
  </StrictMode>,
);
