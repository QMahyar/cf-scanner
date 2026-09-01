<script lang="ts">
  import { onMount } from "svelte";
  import { t } from "../i18n.svelte";
  import { render } from "../qr";

  let {
    payload,
    title,
    onclose,
  }: { payload: string; title: string; onclose: () => void } = $props();

  let canvas: HTMLCanvasElement | null = $state(null);
  let tooLong = $state(false);

  onMount(() => {
    if (canvas) tooLong = !render(canvas, payload);
  });

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
  onkeydown={(e) => e.key === "Escape" && onclose()}
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
