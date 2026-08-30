<script lang="ts">
  import { Check, Copy, KeyRound } from "@lucide/svelte";
  import { errorText } from "../store.svelte";
  import { api } from "../api";
  import { t } from "../i18n.svelte";
  import type { FormState } from "../formState";

  let {
    form = $bindable(),
  }: {
    form: FormState;
  } = $props();

  let licenseInput = $state("");
  let registering = $state(false);
  let registerError = $state<string | null>(null);
  let offerOverwrite = $state(false);
  let registeredConf = $state("");
  let confCopied = $state(false);

  async function registerWarp(overwrite: boolean) {
    registering = true;
    registerError = null;
    offerOverwrite = false;
    try {
      const res = await api.warpRegister(licenseInput.trim() || null, overwrite);
      registeredConf = res.wgconf;
    } catch (e) {
      const msg = errorText(e);
      registerError = msg;
      offerOverwrite = /overwrite/i.test(msg);
    }
    registering = false;
  }

  async function copyConf() {
    try {
      await navigator.clipboard.writeText(registeredConf);
      confCopied = true;
      setTimeout(() => (confCopied = false), 1200);
    } catch {
      /* clipboard unavailable */
    }
  }

  function useRegisteredConf() {
    form.wgconf = registeredConf;
    form.verifyWarp = true;
    registeredConf = "";
    registerError = null;
  }
</script>

<div
  class="fade-in rounded-md border px-3 py-3 span-all"
  style="border-color: oklch(100% 0 0 / 8%)"
>
  <div class="flex flex-wrap items-end gap-2">
    <label class="text-xs" style="color: var(--ink-muted)">
      {t("pro.warp.licenseLabel")}
      <input
        class="field mono mt-1 !w-56"
        bind:value={licenseInput}
        maxlength="256"
        placeholder={t("pro.warp.licensePlaceholder")}
      />
    </label>
    <button
      type="button"
      class="btn btn-secondary btn-sm"
      onclick={() => registerWarp(false)}
      disabled={registering}
      data-state={registering ? "loading" : undefined}
      title={t("pro.warp.registerTitle")}
    >
      <KeyRound class="size-3.5" />
      {registering ? t("pro.warp.registering") : t("pro.warp.register")}
    </button>
  </div>

  {#if registerError}
    <div class="fade-in mt-2 flex flex-wrap items-center gap-2 text-xs">
      <span role="alert" style="color: var(--bad)">{registerError}</span>
      {#if offerOverwrite && !registering}
        <button
          type="button"
          class="btn btn-secondary btn-sm"
          onclick={() => registerWarp(true)}
          title={t("pro.warp.overwriteTitle")}
        >
          {t("pro.warp.overwrite")}
        </button>
      {/if}
    </div>
  {/if}

  {#if registeredConf}
    <div class="fade-in mt-3">
      <p class="text-xs font-semibold" style="color: var(--good)">
        {t("pro.warp.registeredHeading")}
      </p>
      <textarea
        class="field mono mt-1 w-full"
        rows="5"
        readonly
        value={registeredConf}
      ></textarea>
      <div class="mt-2 flex flex-wrap gap-2">
        <button type="button" class="btn btn-secondary btn-sm" onclick={copyConf}>
          {#if confCopied}
            <Check class="size-3.5" style="color: var(--good)" /> {t("pro.warp.copied")}
          {:else}
            <Copy class="size-3.5" /> {t("pro.warp.copy")}
          {/if}
        </button>
        <button
          type="button"
          class="btn btn-primary btn-sm"
          onclick={useRegisteredConf}
          title={t("pro.warp.useInVerifyTitle")}
        >
          {t("pro.warp.useInVerify")}
        </button>
      </div>
    </div>
  {/if}
</div>
