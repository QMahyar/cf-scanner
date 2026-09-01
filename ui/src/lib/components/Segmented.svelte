<script lang="ts">
  type Option = { value: string; label: string };
  let {
    options,
    value,
    onchange,
    label,
  }: { options: Option[]; value: string; onchange: (v: string) => void; label: string } = $props();
</script>

<div class="seg" role="radiogroup" aria-label={label}>
  {#each options as opt (opt.value)}
    <button
      type="button"
      role="radio"
      aria-checked={value === opt.value}
      onclick={() => onchange(opt.value)}
    >{opt.label}</button
    >
  {/each}
</div>
