<script lang="ts">
  import { FolderOpen, Save, Trash2 } from "@lucide/svelte";
  import { api, assertOk, type ProfilePayload } from "../api";
  import { errorText } from "../store.svelte";
  import {
    buildConfig,
    formStateFromConfig,
    FormValidationError,
  } from "../formState";
  import type { FormState } from "../formState";
  import { t } from "../i18n.svelte";

  let {
    form,
    onload,
  }: {
    form: FormState;
    onload: () => void;
  } = $props();

  let profiles = $state<ProfilePayload[]>([]);
  let selectedProfile = $state("");
  let profileNameInput = $state("");
  let profileBusy = $state(false);
  let profileStatus = $state<{ ok: boolean; text: string } | null>(null);

  async function refreshProfiles() {
    profiles = await api.profiles();
    if (!profiles.some((p) => p.name === selectedProfile))
      selectedProfile = "";
  }

  function loadSelectedProfile() {
    const p = profiles.find((x) => x.name === selectedProfile);
    if (!p) return;
    Object.assign(form, formStateFromConfig(p.config));
    onload();
  }

  async function saveProfile() {
    const name = profileNameInput.trim();
    if (!name) {
      profileStatus = { ok: false, text: t("pro.profile.needName") };
      return;
    }
    profileBusy = true;
    try {
      await assertOk(await api.saveProfile(name, buildConfig(form)));
      profileStatus = { ok: true, text: t("pro.profile.saved", { name }) };
      profileNameInput = "";
      await refreshProfiles();
      selectedProfile = name;
    } catch (e) {
      profileStatus = {
        ok: false,
        text: e instanceof FormValidationError ? e.message : errorText(e),
      };
    }
    profileBusy = false;
  }

  async function deleteSelectedProfile() {
    if (!selectedProfile || !confirm(t("pro.profile.deleteConfirm", { name: selectedProfile })))
      return;
    profileBusy = true;
    const deleted = selectedProfile;
    try {
      await assertOk(await api.deleteProfile(deleted));
      profileStatus = { ok: true, text: t("pro.profile.deleted", { name: deleted }) };
      await refreshProfiles();
    } catch (e) {
      profileStatus = { ok: false, text: errorText(e) };
    }
    profileBusy = false;
  }

  export { refreshProfiles };
</script>

<div
  class="mb-4 flex flex-wrap items-center gap-2 border-b pb-4"
  style="border-color: oklch(100% 0 0 / 6%)"
>
  <span
    class="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider"
    style="color: var(--ink-muted)"
  >
    <FolderOpen class="size-3.5" style="color: var(--accent)" /> {t("pro.profile.heading")}
  </span>
  <select
    class="field !w-auto text-xs"
    bind:value={selectedProfile}
    onchange={loadSelectedProfile}
    disabled={profiles.length === 0}
    title={t("pro.profile.loadTitle")}
  >
    <option value="">
      {profiles.length === 0 ? t("pro.profile.noSaved") : t("pro.profile.loadPlaceholder")}
    </option>
    {#each profiles as p (p.name)}
      <option value={p.name}>{p.name}</option>
    {/each}
  </select>
  <input
    class="field mono !w-44 text-xs"
    placeholder={t("pro.profile.namePlaceholder")}
    maxlength="64"
    bind:value={profileNameInput}
  />
  <button
    class="btn btn-secondary btn-sm"
    onclick={saveProfile}
    disabled={profileBusy}
    title={t("pro.profile.saveTitle")}
  >
    <Save class="size-3.5" /> {t("pro.profile.save")}
  </button>
  <button
    class="btn btn-secondary btn-sm"
    onclick={deleteSelectedProfile}
    disabled={!selectedProfile || profileBusy}
    title={t("pro.profile.deleteTitle")}
  >
    <Trash2 class="size-3.5" /> {t("pro.profile.delete")}
  </button>
  {#if profileStatus}
    <span
      class="fade-in text-xs"
      role="status"
      style={profileStatus.ok
        ? "color: var(--good)"
        : "color: var(--bad)"}
    >
      {profileStatus.text}
    </span>
  {/if}
</div>
