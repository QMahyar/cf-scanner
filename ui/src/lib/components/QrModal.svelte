<script lang="ts">
  import { onMount } from "svelte";
  import { t } from "../i18n.svelte";
  import { render } from "../qr";

  let {
    payload,
    title,
    onclose,
  }: { payload: string; title: string; onclose: () => void } = $props();

  let modal: HTMLDivElement | null = $state(null);
  let canvas: HTMLCanvasElement | null = $state(null);
  let tooLong = $state(false);

  onMount(() => {
    if (canvas) tooLong = !render(canvas, payload);
    const prev = document.activeElement as HTMLElement | null;
    modal?.focus();
    return () => prev?.focus?.();
  });

  function onkeydown(e: KeyboardEvent) {
    if (e.key === "Escape") {
      onclose();
      return;
    }
    if (e.key !== "Tab" || !modal) return;
    const focusables = [
      ...modal.querySelectorAll<HTMLElement>("button:not([disabled])"),
    ];
    if (focusables.length === 0) return;
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    const active = document.activeElement;
    if (e.shiftKey && (active === first || active === modal)) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && (active === last || active === modal)) {
      e.preventDefault();
      first.focus();
    }
  }

  function download() {
    if (!canvas || tooLong) return;
    const a = document.createElement("a");
    a.download = "cf-scanner-qr.png";
    a.href = canvas.toDataURL("image/png");
    a.click();
  }
</script>

<div
  class="modal"
  role="dialog"
  aria-modal="true"
  aria-labelledby="qr-title"
  tabindex="-1"
  bind:this={modal}
  {onkeydown}
  onclick={(e) => e.target === e.currentTarget && onclose()}
>
  <div class="modal__panel">
    <h2 class="modal__title" id="qr-title">{title}</h2>
    {#if tooLong}
      <p class="field__hint" style="margin-block-end: 12px" role="alert">{t("qr.tooLong")}</p>
    {:else}
      <div class="qr-wrap"><canvas bind:this={canvas} style="width:280px;height:280px;display:block;max-width:64vw;max-height:64vw"></canvas></div>
      <p class="field__hint" style="margin-block-end: 12px">{t("qr.hint")}</p>
    {/if}
    <div class="modal__actions">
      <button type="button" class="btn btn-ghost btn-sm" onclick={download} disabled={tooLong}>
        {t("qr.download")}
      </button>
      <button type="button" class="btn btn-ghost btn-sm" onclick={onclose}>
        {t("common.close")}
      </button>
    </div>
  </div>
</div>
