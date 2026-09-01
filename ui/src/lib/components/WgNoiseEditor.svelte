<script lang="ts">
  import { RotateCcw } from "@lucide/svelte";
  import { t } from "../i18n.svelte";

  /** Client-side AmneziaWG noise editor (research §5). Edits the junk /
   * init-padding / magic-header keys of the pasted WireGuard/AmneziaWG
   * config in place — plain INI or base64-INI URIs (awg:// wg://
   * wireguard://). Everything else in the config is preserved byte-for-byte;
   * keys never leave the page. */
  let { text, onchange }: { text: string; onchange: (next: string) => void } =
    $props();

  type NoiseKey = "Jc" | "Jmin" | "Jmax" | "S1" | "S2" | "H1" | "H2" | "H3" | "H4";
  const KEYS: NoiseKey[] = ["Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"];
  const H_KEYS: NoiseKey[] = ["H1", "H2", "H3", "H4"];

  function b64urlDecode(input: string): string | null {
    try {
      const std = input.replace(/-/g, "+").replace(/_/g, "/");
      const padded = std + "=".repeat((4 - (std.length % 4)) % 4);
      const bin = atob(padded);
      return new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
    } catch {
      return null;
    }
  }

  function b64urlEncode(ini: string): string {
    const bytes = new TextEncoder().encode(ini);
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  /** Split the pasted config into (scheme, ini). Null when the payload isn't
   * an editable INI (subscription blobs, JSON, garbage). */
  function splitContainer(raw: string): { scheme: string | null; ini: string } | null {
    const trimmed = raw.trim();
    const uri = /^(awg|wg|wireguard):\/\/(.*)$/is.exec(trimmed);
    if (uri) {
      const ini = b64urlDecode(uri[2]);
      if (ini === null || !/\[interface\]/i.test(ini)) return null;
      return { scheme: uri[1].toLowerCase(), ini };
    }
    if (!/\[interface\]/i.test(trimmed)) return null;
    return { scheme: null, ini: trimmed };
  }

  const container = $derived(splitContainer(text));

  function interfaceBounds(ini: string): { start: number; end: number } {
    const start = ini.search(/\[interface\]/i);
    const peer = ini.slice(start + 1).search(/\[(?!interface)/i);
    const end = peer === -1 ? ini.length : start + 1 + peer;
    return { start, end };
  }

  function readKey(ini: string, key: NoiseKey): string | null {
    const { start, end } = interfaceBounds(ini);
    const m = new RegExp(`^[ \\t]*${key}[ \\t]*=[ \\t]*([^\\s#;]+)`, "im").exec(
      ini.slice(start, end),
    );
    return m ? m[1] : null;
  }

  /** Replace the key's line inside [Interface], or insert it right after the
   * section header when absent — every other byte stays identical. */
  function writeKey(ini: string, key: NoiseKey, value: string): string {
    const { start, end } = interfaceBounds(ini);
    const section = ini.slice(start, end);
    const lineRe = new RegExp(`^[ \\t]*${key}[ \\t]*=.*$`, "im");
    if (lineRe.test(section)) {
      const replaced = section.replace(lineRe, `${key} = ${value}`);
      return ini.slice(0, start) + replaced + ini.slice(end);
    }
    const headerEnd = section.indexOf("\n");
    const insertAt = headerEnd === -1 ? section.length : headerEnd + 1;
    const nextSection = section.slice(0, insertAt) + `${key} = ${value}\n` + section.slice(insertAt);
    return ini.slice(0, start) + nextSection + ini.slice(end);
  }

  const values = $derived.by(() => {
    const out: Record<NoiseKey, string> = {
      Jc: "", Jmin: "", Jmax: "", S1: "", S2: "", H1: "", H2: "", H3: "", H4: "",
    };
    if (!container) return out;
    for (const k of KEYS) out[k] = readKey(container.ini, k) ?? "";
    return out;
  });

  function pushIni(nextIni: string): void {
    if (!container) return;
    onchange(container.scheme ? `${container.scheme}://${b64urlEncode(nextIni)}` : nextIni);
  }

  function setField(key: NoiseKey, raw: string): void {
    if (!container) return;
    const clean = raw.trim();
    if (clean === "") {
      // Clearing a field removes its line entirely (engine treats missing
      // keys as defaults), except H* which must stay explicit once present.
      if (!H_KEYS.includes(key)) {
        const { start, end } = interfaceBounds(container.ini);
        const section = container.ini
          .slice(start, end)
          .replace(new RegExp(`^[ \\t]*${key}[ \\t]*=.*\\n?`, "im"), "");
        pushIni(container.ini.slice(0, start) + section + container.ini.slice(end));
        return;
      }
      return;
    }
    pushIni(writeKey(container.ini, key, clean));
  }

  /** Research §5 presets — values validated against amneziawg kernel limits
   * and real provider configs. */
  const PRESETS: Record<"off" | "light" | "heavy", Record<NoiseKey, string>> = {
    off: { Jc: "0", Jmin: "0", Jmax: "0", S1: "0", S2: "0", H1: "1", H2: "2", H3: "3", H4: "4" },
    light: {
      Jc: "4", Jmin: "50", Jmax: "300", S1: "30", S2: "40",
      H1: "100000-400000", H2: "5000000-9000000",
      H3: "50000000-90000000", H4: "600000000-900000000",
    },
    heavy: {
      Jc: "8", Jmin: "64", Jmax: "1024", S1: "64", S2: "48",
      H1: "123456-654321", H2: "7654321-8765432",
      H3: "31415926-41415926", H4: "271828182-371828182",
    },
  };

  function applyPreset(name: keyof typeof PRESETS): void {
    if (!container) return;
    let next = container.ini;
    for (const k of KEYS) next = writeKey(next, k, PRESETS[name][k]);
    pushIni(next);
  }

  function parseRange(v: string): [number, number] | null {
    const m = /^(\d+)(?:-(\d+))?$/.exec(v.trim());
    if (!m) return null;
    const lo = Number(m[1]);
    const hi = m[2] !== undefined ? Number(m[2]) : lo;
    return lo <= hi ? [lo, hi] : null;
  }

  const issues = $derived.by(() => {
    const list: string[] = [];
    if (!container) return list;
    const int = (k: NoiseKey): number | null => {
      const v = values[k];
      if (v === "") return null;
      return /^\d+$/.test(v.trim()) ? Number(v) : NaN;
    };
    const jc = int("Jc");
    if (jc !== null && (Number.isNaN(jc) || jc < 0 || jc > 128))
      list.push("Jc: 0–128");
    const jmin = int("Jmin");
    const jmax = int("Jmax");
    for (const [label, v] of [["Jmin", jmin], ["Jmax", jmax]] as const)
      if (v !== null && (Number.isNaN(v) || v >= 1280)) list.push(`${label}: 0–1279`);
    if (jc !== null && jc > 0 && jmin !== null && jmax !== null &&
        !Number.isNaN(jmin) && !Number.isNaN(jmax) && jmin >= jmax)
      list.push("need Jmin < Jmax");
    const s1 = int("S1");
    const s2 = int("S2");
    if (s1 !== null && (Number.isNaN(s1) || s1 > 1132)) list.push("S1: 0–1132");
    if (s2 !== null && (Number.isNaN(s2) || s2 > 1188)) list.push("S2: 0–1188");
    if (s1 !== null && s2 !== null && !Number.isNaN(s1) && !Number.isNaN(s2) && s1 + 56 === s2)
      list.push("S1+56 must not equal S2");
    const ranges: [string, [number, number]][] = [];
    for (const k of H_KEYS) {
      const v = values[k];
      if (v === "") continue;
      const r = parseRange(v);
      if (!r || r[0] < 5 || r[1] > 2147483647)
        list.push(`${k}: 5–2147483647 or lo-hi`);
      else ranges.push([k, r]);
    }
    for (let i = 0; i < ranges.length; i++)
      for (let j = i + 1; j < ranges.length; j++) {
        const [, a] = ranges[i];
        const [, b] = ranges[j];
        if (a[0] <= b[1] && b[0] <= a[1]) list.push("H1–H4 ranges must not overlap");
      }
    return [...new Set(list)];
  });
</script>

{#if container}
  <div
    class="fade-in rounded-md border px-3 py-3"
    style="border-color: var(--rule)"
  >
    <div class="flex flex-wrap items-center justify-between gap-2">
      <span class="mono text-[11px] font-semibold uppercase tracking-wider" style="color: var(--ink-muted)">
        {container.scheme ? t("wgnoise.headingScheme", { scheme: container.scheme }) : t("wgnoise.headingIni")}
      </span>
      <span class="flex items-center gap-1">
        {#each Object.keys(PRESETS) as p (p)}
          <button
            type="button"
            class="pill"
            title={t("wgnoise.presetTitle", { preset: p })}
            onclick={() => applyPreset(p as keyof typeof PRESETS)}
          >
            <RotateCcw class="size-3" aria-hidden="true" /> {p}
          </button>
        {/each}
      </span>
    </div>
    <div class="mt-2 grid grid-cols-3 gap-2 sm:grid-cols-5">
      {#each KEYS as k (k)}
        {@const bad = issues.some((i) => i.startsWith(k))}
        <label class="text-[11px]" style="color: var(--ink-muted)">
          {k}
          <input
            class="field mono mt-0.5 !px-2 text-center text-xs"
            value={values[k]}
            placeholder={H_KEYS.includes(k) ? t("wgnoise.placeholder.lohi") : t("wgnoise.placeholder.dash")}
            oninput={(e) => setField(k, e.currentTarget.value)}
            aria-invalid={bad ? "true" : undefined}
          />
        </label>
      {/each}
    </div>
    {#if issues.length > 0}
      <p class="fade-in mt-2 text-[11px]" role="alert" style="color: var(--bad)">
        {issues.join(" · ")}
      </p>
    {:else}
      <p class="mt-2 text-[11px]" style="color: var(--ink-muted)">
        {t("wgnoise.limits")}
      </p>
    {/if}
  </div>
{/if}
