<script lang="ts">
  let { tip }: { tip: string } = $props();
</script>

<span class="help-wrap">
  <button type="button" class="help-trigger" aria-label={tip} title={tip}>?</button>
  <span class="help-pop" role="tooltip">{tip}</span>
</span>
