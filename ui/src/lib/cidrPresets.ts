/** Curated exclusion presets for the scan form's CIDR block.
 * EXCLUDE_WARP_INGRESS — Cloudflare WARP ingress ranges from the Cloudflare
 * One firewall docs ("WARP ingress" IPs). They terminate WireGuard tunnels,
 * not the CDN proxy, so probing them in CDN mode burns candidate slots on
 * guaranteed non-answers. */
export const EXCLUDE_WARP_INGRESS: string[] = [
  "162.159.192.0/24",
  "162.159.193.0/24",
];
