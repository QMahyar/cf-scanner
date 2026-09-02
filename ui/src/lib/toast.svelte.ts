export type ToastKind = "ok" | "err";
export type ToastEntry = {
  id: number;
  msg: string;
  kind: ToastKind;
  leaving: boolean;
  total: number;
};

const MAX = 3;
const OK_MS = 3500;
const ERR_MS = 6000;

let entries = $state<ToastEntry[]>([]);
let nextId = 1;

function remove(id: number): void {
  const t = entries.find((e) => e.id === id);
  if (!t || t.leaving) return;
  t.leaving = true;
  setTimeout(() => {
    entries = entries.filter((e) => e.id !== id);
  }, 220);
}

export function toast(msg: string, kind: ToastKind = "ok"): void {
  const id = nextId++;
  const total = kind === "err" ? ERR_MS : OK_MS;
  entries = [...entries.slice(-(MAX - 1)), { id, msg, kind, leaving: false, total }];
  setTimeout(() => remove(id), total);
}

export function toasts(): ToastEntry[] {
  return entries;
}

export function dismissToast(id: number): void {
  remove(id);
}
