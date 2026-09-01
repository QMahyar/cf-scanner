<script lang="ts">
  import { FolderOpen } from "@lucide/svelte";
  import { t } from "../i18n.svelte";
  import HelpPop from "./HelpPop.svelte";
  import type { FormField, FormState } from "../formState";
  import WgNoiseEditor from "./WgNoiseEditor.svelte";

  let {
    form = $bindable(),
    fieldErrors,
    touched = $bindable(),
    serverFieldErrors = $bindable(),
  }: {
    form: FormState;
    fieldErrors: Partial<Record<FormField, string>>;
    touched: Partial<Record<FormField, boolean>>;
    serverFieldErrors: Partial<Record<FormField, string>>;
  } = $props();

  const WGCONF_MAX_BYTES = 64 * 1024;
  let wgconfFileInput = $state<HTMLInputElement | null>(null);
  let wgconfFileName = $state("");
  let wgconfFileError = $state<string | null>(null);

  async function loadWgconfFile(
    e: Event & { currentTarget: EventTarget & HTMLInputElement },
  ) {
    const input = e.currentTarget;
    const file = input.files?.[0] ?? null;
    input.value = "";
    wgconfFileError = null;
    if (!file) return;
    if (file.size > WGCONF_MAX_BYTES) {
      wgconfFileError = t("pro.warp.wgconfSizeError", { name: file.name, kb: Math.ceil(file.size / 1024) });
      return;
    }
    try {
      form.wgconf = await file.text();
      form.verifyWarp = true;
      wgconfFileName = file.name;
      delete serverFieldErrors.wgconf;
    } catch {
      wgconfFileError = t("pro.warp.wgconfReadError", { name: file.name });
    }
  }
</script>

<div
  class="rounded-md border px-3 py-3 span-all"
  style="border-color: var(--rule); background: var(--wash)"
>
  <p class="mb-2 text-xs font-semibold" style="color: var(--ink)">{t("pro.warp.identityGroup")}</p>
  <div class="text-xs" style="color: var(--ink-muted)">
    <label class="block">
      <span class="field__label-row">
        <span class="field__label">{t("pro.warp.wgconfLabel")}</span>
        <HelpPop tip={t("tooltip.wgconf")} />
      </span>
    <textarea
      class="field mono mt-1"
      rows="3"
      name="wgconf"
      aria-invalid={fieldErrors.wgconf ? "true" : undefined}
      aria-describedby={fieldErrors.wgconf ? "err-wgconf" : undefined}
      bind:value={form.wgconf}
      onchange={() => {
        if (form.wgconf.trim()) {
          form.verifyWarp = true;
          touched.verifyWarp = true;
        }
      }}
    ></textarea>
  </label>
  {#if fieldErrors.wgconf}
    <span
      id="err-wgconf"
      class="fade-in mt-1 block text-[11px] leading-snug"
      style="color: var(--bad)"
      role="alert">{fieldErrors.wgconf}</span
    >
  {/if}
  <div class="mt-1.5 flex flex-wrap items-center gap-2">
    <button
      type="button"
      class="btn btn-secondary btn-sm"
      title={t("pro.warp.wgconfLoadTitle")}
      onclick={() => wgconfFileInput?.click()}
    >
      <FolderOpen class="size-3.5" /> {t("pro.warp.wgconfLoad")}
    </button>
    {#if wgconfFileName}
      <span
        class="fade-in mono max-w-48 truncate text-[11px]"
        style="color: var(--ink-muted)"
        title={wgconfFileName}>{wgconfFileName}</span
      >
    {/if}
  </div>
  {#if wgconfFileError}
    <p class="fade-in mt-1 text-[11px]" role="alert" style="color: var(--bad)">
      {wgconfFileError}
    </p>
  {/if}
  <div class="mt-2">
    <WgNoiseEditor
      text={form.wgconf}
      onchange={(next) => {
        form.wgconf = next;
        touched.wgconf = true;
        delete serverFieldErrors.wgconf;
      }}
    />
  </div>
  <input
    bind:this={wgconfFileInput}
    class="hidden"
    type="file"
    accept=".conf,.txt"
    onchange={loadWgconfFile}
  />
  </div>
  <label class="switch" style="color: var(--ink-muted)">
    <input type="checkbox" name="verifyWarp" bind:checked={form.verifyWarp} disabled={!form.wgconf} />
    <span class="switch__track"><span class="switch__thumb"></span></span>
    <span class="switch__label text-xs">{t("pro.warp.verify")}</span>
  </label>
  <p class="mt-1 text-[11px]" style="color: var(--ink-muted)">{t("pro.warp.verifyHint")}</p>
</div>
