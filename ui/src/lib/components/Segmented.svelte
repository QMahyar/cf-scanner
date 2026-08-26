<script lang="ts">
  type Option = { value: string; label: string };
  let {
    options,
    value,
    onchange,
    label,
  }: { options: Option[]; value: string; onchange: (v: string) => void; label: string } = $props();
</script>

<div role="group" aria-label={label} class="flex gap-1.5">
  {#each options as opt (opt.value)}
    <button
      type="button"
      class="pill"
      style={value === opt.value
        ? "background: var(--accent); color: var(--accent-ink)"
        : "background: var(--paper-3); color: var(--ink)"}
      aria-pressed={value === opt.value}
      onclick={() => onchange(opt.value)}
    >{opt.label}</button>
  {/each}
</div>
