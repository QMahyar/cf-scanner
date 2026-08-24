import { mount } from "svelte";
import "./app.css";
import { applyDocumentLang } from "./lib/i18n.svelte";
import App from "./App.svelte";

// Direction/lang must land on <html> before first paint (research §8: no
// RTL FOUC on the Persian default path).
applyDocumentLang();

const app = mount(App, { target: document.getElementById("app")! });

export default app;
