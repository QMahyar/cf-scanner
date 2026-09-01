export type Theme = "light" | "dark";
export type Accent = "cyan" | "violet" | "green" | "amber";

const THEME_KEY = "cfs_theme";
const ACCENT_KEY = "cfs_accent";
export const ACCENTS: ReadonlyArray<{ id: Accent; label: string }> = [
  { id: "cyan", label: "Cyan" },
  { id: "violet", label: "Violet" },
  { id: "green", label: "Green" },
  { id: "amber", label: "Amber" },
];

/** Mirrors Q Proxy's head bootstrap: stored value wins, otherwise the OS
 * preference decides light vs dark. Runs at mount and again from the
 * inline <head> script (index.html) so no flash happens before hydration. */
export function resolveInitialTheme(): Theme {
  try {
    const s = localStorage.getItem(THEME_KEY);
    if (s === "light" || s === "dark") return s;
  } catch {
    /* storage unavailable */
  }
  try {
    if (window.matchMedia?.("(prefers-color-scheme: light)").matches) return "light";
  } catch {
    /* matchMedia unavailable */
  }
  return "dark";
}

export function resolveInitialAccent(): Accent {
  try {
    const a = localStorage.getItem(ACCENT_KEY);
    if (a === "violet" || a === "green" || a === "amber") return a;
  } catch {
    /* storage unavailable */
  }
  return "cyan";
}

function apply(theme: Theme, accent: Accent): void {
  const el = document.documentElement;
  el.dataset.theme = theme;
  el.style.colorScheme = theme;
  if (accent === "cyan") delete el.dataset.accent;
  else el.dataset.accent = accent;
}

let current = $state<{ theme: Theme; accent: Accent }>({
  theme: "dark",
  accent: "cyan",
});

/** Apply persisted/OS theme + accent before first paint; returns nothing. */
export function initTheme(): void {
  current = { theme: resolveInitialTheme(), accent: resolveInitialAccent() };
  apply(current.theme, current.accent);
}

export function theme(): Theme {
  return current.theme;
}
export function accent(): Accent {
  return current.accent;
}

export function setTheme(next: Theme): void {
  current.theme = next;
  apply(next, current.accent);
  try {
    localStorage.setItem(THEME_KEY, next);
  } catch {
    /* storage unavailable */
  }
}

export function toggleTheme(): void {
  setTheme(current.theme === "dark" ? "light" : "dark");
}

export function setAccent(next: Accent): void {
  current.accent = next;
  apply(current.theme, next);
  try {
    localStorage.setItem(ACCENT_KEY, next);
  } catch {
    /* storage unavailable */
  }
}
