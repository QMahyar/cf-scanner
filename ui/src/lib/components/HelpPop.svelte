<script lang="ts">
  /** Q Proxy help-pop: ?-icon with hover/focus popover. Text comes from
   * i18n; `tip` is already translated by the caller. */
  let { tip }: { tip: string } = $props();
</script>

<span class="help-wrap">
  <button type="button" class="help-trigger" aria-label={tip} title={tip}>?</button>
  <span class="help-pop" role="tooltip">{tip}</span>
</span>
