<script lang="ts">
  import { Info } from "@lucide/svelte";
  import { api } from "../api";
  import { MAX_CIDRS, parseCidr, parseEndpoint } from "../validators";
  import { EXCLUDE_WARP_INGRESS } from "../cidrPresets";
  import { t } from "../i18n.svelte";
  import type { FormField, FormState } from "../formState";
  import type { RangesPayload } from "../api";

  let {
    form,
    fieldErrors,
    touched,
    serverFieldErrors,
    onNormalize,
  }: {
    form: FormState;
    fieldErrors: Partial<Record<FormField, string>>;
    touched: Partial<Record<FormField, boolean>>;
    serverFieldErrors: Partial<Record<FormField, string>>;
    onNormalize: (field: "customCidrs" | "exclude") => void;
  } = $props();

  let rangesInfo = $state<RangesPayload | null>(null);

  const RANGES_MAX_BYTES = 256 * 1024;
  let rangesFileInput = $state<HTMLInputElement | null>(null);
  let rangesNote = $state<{ ok: boolean; text: string } | null>(null);

  function importRangesFile(
    e: Event & { currentTarget: EventTarget & HTMLInputElement },
  ) {
    const input = e.currentTarget;
    const file = input.files?.[0] ?? null;
    input.value = "";
    rangesNote = null;
    if (!file) return;
    if (file.size > RANGES_MAX_BYTES) {
      rangesNote = {
        ok: false,
        text: t("pro.warp.rangesSizeError", { name: file.name, kb: Math.ceil(file.size / 1024) }),
      };
      return;
    }
    void file.text().then((raw) => {
      const existing = form.customCidrs
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean);
      const seen = new Set(existing);
      let imported = 0;
      let skipped = 0;
      for (const line of raw.split(/\r?\n/).map((s) => s.trim())) {
        if (!line || line.startsWith("#")) continue;
        let entry: string | null = null;
        const v = parseCidr(line);
        if (v.ok) entry = line;
        else if (parseEndpoint(line).ok) entry = `${line}/32`;
        if (entry === null || existing.length >= MAX_CIDRS) {
          skipped += 1;
          continue;
        }
        if (!seen.has(entry)) {
          seen.add(entry);
          existing.push(entry);
          imported += 1;
        }
      }
      form.customCidrs = existing.join("\n");
      touched.customCidrs = true;
      delete serverFieldErrors.customCidrs;
      rangesNote = {
        ok: imported > 0,
        text: imported === 0 && skipped === 0 ? t("pro.warp.rangesEmpty", { name: file.name }) : skipped > 0 ? t("pro.warp.rangesImportedSkipped", { count: imported, s: imported === 1 ? "" : "s", skipped }) : t("pro.warp.rangesImported", { count: imported, s: imported === 1 ? "" : "s" }),
      };
    });
  }

  async function loadRangeInfo() {
    try {
      rangesInfo = await api.ranges();
    } catch (e) {
      /* non-critical; keep rangesInfo null */
    }
  }

  function excludeWarpIngress() {
    const kept = form.exclude
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);
    const seen = new Set(kept);
    form.exclude = [
      ...kept,
      ...EXCLUDE_WARP_INGRESS.filter((c) => !seen.has(c)),
    ].join("\n");
    touched.exclude = true;
    delete serverFieldErrors.exclude;
  }

  function clearExclusions() {
    form.exclude = "";
    touched.exclude = true;
    delete serverFieldErrors.exclude;
  }
</script>

<details class="mt-4">
  <summary class="cursor-pointer text-xs font-semibold" style="color: var(--ink-muted)">
    {t("pro.section.customCidrs")}
  </summary>
  <div class="mt-2 flex flex-wrap items-center gap-2">
    <button
      type="button"
      class="btn btn-secondary btn-sm"
      onclick={loadRangeInfo}
      title={t("pro.range.infoTitle")}
    >
      <Info class="size-3.5" /> {t("pro.range.button")}
    </button>
    {#if rangesInfo}
      <span
        class="mono fade-in text-[11px]"
        role="status"
        style="color: var(--ink-muted)"
      >
        {t("pro.range.info", { count: rangesInfo.host_count.toLocaleString("en-US"), date: rangesInfo.last_updated ?? t("pro.range.bundled") })}
      </span>
    {/if}
  </div>
  <div class="mt-3 grid gap-4 grid-form">
    <label class="text-xs" style="color: var(--ink-muted)">
      {t("pro.field.customCidrs")}
      <textarea
        class="field mono mt-1"
        rows="3"
        name="customCidrs"
        aria-invalid={fieldErrors.customCidrs ? "true" : undefined}
        aria-describedby={fieldErrors.customCidrs ? "err-customCidrs" : undefined}
        bind:value={form.customCidrs}
        onchange={() => onNormalize("customCidrs")}></textarea>
      {#if fieldErrors.customCidrs}
        <span
          id="err-customCidrs"
          class="fade-in mt-1 block text-[11px] leading-snug"
          style="color: var(--bad)"
          role="alert">{fieldErrors.customCidrs}</span
        >
      {/if}
    </label>
    <label class="text-xs" style="color: var(--ink-muted)">
      {t("pro.field.exclude")}
      <textarea
        class="field mono mt-1"
        rows="3"
        name="exclude"
        aria-invalid={fieldErrors.exclude ? "true" : undefined}
        aria-describedby={fieldErrors.exclude ? "err-exclude" : undefined}
        bind:value={form.exclude}
        onchange={() => onNormalize("exclude")}></textarea>
      {#if fieldErrors.exclude}
        <span
          id="err-exclude"
          class="fade-in mt-1 block text-[11px] leading-snug"
          style="color: var(--bad)"
          role="alert">{fieldErrors.exclude}</span
        >
      {/if}
    </label>
  </div>
  <div class="mt-2 flex flex-wrap items-center gap-1.5">
    <button
      type="button"
      class="pill cursor-pointer"
      style="background: var(--paper-3); color: var(--ink)"
      title={t("pro.field.excludeWarpTitle")}
      onclick={excludeWarpIngress}
    >{t("pro.field.excludeWarp")}</button>
    {#if form.mode === "Cdn"}
      <button
        type="button"
        class="pill cursor-pointer"
        style="background: var(--paper-3); color: var(--ink)"
        title={t("pro.field.importListTitle")}
        onclick={() => rangesFileInput?.click()}
      >{t("pro.field.importList")}</button>
    {/if}
    <button
      type="button"
      class="pill cursor-pointer"
      style="color: var(--ink-muted)"
      title={t("pro.field.clearTitle")}
      onclick={clearExclusions}
    >{t("pro.field.clear")}</button>
    {#if rangesNote}
      <span
        class="fade-in mono text-[10px]"
        role="status"
        style={rangesNote.ok ? "color: var(--good)" : "color: var(--bad)"}
      >
        {rangesNote.text}
      </span>
    {/if}
  </div>
  <input
    bind:this={rangesFileInput}
    class="hidden"
    type="file"
    accept=".txt,.csv,.list,.text,text/plain"
    onchange={importRangesFile}
  />
</details>
