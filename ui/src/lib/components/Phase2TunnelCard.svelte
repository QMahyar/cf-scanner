<script lang="ts">
  import { Download } from "@lucide/svelte";
  import { t } from "../i18n.svelte";
  import type { FormField, FormState } from "../formState";
  import type { XrayStatusPayload } from "../api";
  import { defaultFormState } from "../formState";

  let {
    form,
    fieldErrors,
    onNormalize,
    xray,
    xrayBusy,
    xrayError,
    onDownloadXray,
  }: {
    form: FormState;
    fieldErrors: Partial<Record<FormField, string>>;
    onNormalize: (field: "configsText") => void;
    xray: XrayStatusPayload | null;
    xrayBusy: boolean;
    xrayError: string | null;
    onDownloadXray: () => void;
  } = $props();

  let tunnelAdvancedOpen = $state(false);

  const DEFAULT_PROBE_URL = defaultFormState().probeUrl;

  const tunnelAdvancedSummary = $derived.by(() => {
    const bits: string[] = [];
    if (form.fragment !== "off") bits.push(form.fragment);
    const sniList = form.snis.split(",").map((s) => s.trim()).filter(Boolean);
    if (sniList.length > 0)
      bits.push(sniList[0] + (sniList.length > 1 ? ` +${sniList.length - 1}` : ""));
    const probe = form.probeUrl.trim();
    if (probe && probe !== DEFAULT_PROBE_URL)
      bits.push(probe.length > 28 ? `${probe.slice(0, 28)}…` : probe);
    return bits.join(" · ");
  });
</script>

<div
  class="fade-in mt-4 rounded-md border px-4 py-4"
  style="border-color: var(--rule)"
>
  <div class="mb-3 flex flex-wrap items-center justify-between gap-2">
    <span class="eyebrow">{t("table.tunnel.col")}</span>
    <div class="flex items-center gap-2">
      {#if xray}
        <span
          class="pill"
          title={xray.found ? (xray.path ?? t("pro.xray.foundFallback")) : t("pro.xray.missingUnder", { dir: xray.data_dir ?? "" })}
          style={xray.found
            ? "background: oklch(46% 0.11 155 / 12%); color: var(--good)"
            : "background: var(--bad); color: var(--bad)"}
        >
          xray {xray.found ? xray.version : t("pro.xray.missing")}
        </span>
        {#if !xray.found}
          <button
            type="button"
            class="btn btn-secondary btn-sm"
            onclick={onDownloadXray}
            disabled={xrayBusy}
            data-state={xrayBusy ? "loading" : undefined}
            title={t("pro.xray.downloadTitle", { dir: xray.data_dir ?? "" })}
          >
            <Download class="size-3.5" /> {t("pro.xray.download")}
          </button>
        {/if}
      {/if}
    </div>
  </div>
  {#if xrayError}
    <p class="fade-in -mt-1 mb-3 text-[11px]" role="alert" style="color: var(--bad)">
      {t("pro.xray.error", { msg: xrayError })}
    </p>
  {/if}
  <label class="text-xs" style="color: var(--ink-muted)">
    {t("pro.phase2.configsLabel")}
    <textarea
      class="field mono mt-1"
      rows="3"
      name="configsText"
      aria-invalid={fieldErrors.configsText ? "true" : undefined}
      aria-describedby={fieldErrors.configsText ? "err-configsText" : undefined}
      bind:value={form.configsText}
      onchange={() => onNormalize("configsText")}></textarea>
    {#if fieldErrors.configsText}
      <span
        id="err-configsText"
        class="fade-in mt-1 block text-[11px] leading-snug"
        style="color: var(--bad)"
        role="alert">{fieldErrors.configsText}</span
      >
    {/if}
  </label>
  <details class="mt-3" bind:open={tunnelAdvancedOpen}>
    <summary class="cursor-pointer text-xs font-semibold" style="color: var(--ink-muted)">
      {t("pro.section.tunnelAdvanced")}
      {#if tunnelAdvancedSummary}
        <span class="mono font-normal" style="color: var(--accent)">
          · {tunnelAdvancedSummary}
        </span>
      {/if}
    </summary>
    <div class="mt-3 grid gap-4 grid-form">
      <label class="text-xs" style="color: var(--ink-muted)">
        {t("pro.phase2.fragment")}
        <select class="field mt-1" name="fragment" bind:value={form.fragment}>
          <option>off</option><option>light</option><option>medium</option><option>heavy</option>
        </select>
        {#if fieldErrors.fragment}
          <span
            id="err-fragment"
            class="fade-in mt-1 block text-[11px] leading-snug"
            style="color: var(--bad)"
            role="alert">{fieldErrors.fragment}</span
          >
        {/if}
      </label>
      <label class="text-xs span-all" style="color: var(--ink-muted)">
        {t("pro.phase2.sniLabel")}
        <input
          class="field mono mt-1"
          name="snis"
          placeholder={t("pro.phase2.sniPlaceholder")}
          aria-invalid={fieldErrors.snis ? "true" : undefined}
          aria-describedby={fieldErrors.snis ? "err-snis" : undefined}
          bind:value={form.snis}
        />
        {#if fieldErrors.snis}
          <span
            id="err-snis"
            class="fade-in mt-1 block text-[11px] leading-snug"
            style="color: var(--bad)"
            role="alert">{fieldErrors.snis}</span
          >
        {/if}
      </label>
      <label class="text-xs span-all" style="color: var(--ink-muted)">
        {t("pro.phase2.probeLabel")}
        <input
          class="field mono mt-1"
          name="probeUrl"
          aria-invalid={fieldErrors.probeUrl ? "true" : undefined}
          aria-describedby={fieldErrors.probeUrl ? "err-probeUrl" : undefined}
          bind:value={form.probeUrl}
        />
        {#if fieldErrors.probeUrl}
          <span
            id="err-probeUrl"
            class="fade-in mt-1 block text-[11px] leading-snug"
            style="color: var(--bad)"
            role="alert">{fieldErrors.probeUrl}</span
          >
        {/if}
      </label>
    </div>
  </details>
</div>
