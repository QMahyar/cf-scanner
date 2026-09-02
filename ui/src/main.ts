import { mount } from "svelte";
import "./app.css";
import { applyDocumentLang } from "./lib/i18n.svelte";
import App from "./App.svelte";

applyDocumentLang();

const app = mount(App, { target: document.getElementById("app")! });

export default app;
