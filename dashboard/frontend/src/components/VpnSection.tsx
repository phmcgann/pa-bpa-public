import type { ReactNode } from "react";
import type { Finding, Vpn, VpnGateway, VpnIkeProfile, VpnIpsecProfile } from "../types";
import { cn } from "../lib/cn";
import { Badge } from "./ui/Badge";

const WEAK_CIPHERS = new Set(["des", "3des", "null"]);
const WEAK_HASHES = new Set(["md5", "sha1"]);
const NO_AUTH = new Set(["non-auth", "none"]);

function alg(a: string): string {
  if (a === "non-auth" || a === "none") return "None";
  if (a === "sha1") return "SHA-1";
  return a.toUpperCase().replace(/^SHA(\d)/, "SHA-$1");
}

function group(g: string): string {
  return g === "no-pfs" ? "No PFS" : g.replace(/^group/, "");
}

function hours(h: number): string {
  if (h >= 24 && h % 24 === 0) return `${h / 24} day${h === 24 ? "" : "s"}`;
  if (h >= 1) return `${+h.toFixed(2)} h`;
  return `${Math.round(h * 60)} min`;
}

/** A list of algorithms, each one red when `weak` says so and the rule has an open finding. */
function Algs({ items, weak, flagged, render = alg }: {
  items: string[]; weak: (a: string) => boolean; flagged: boolean; render?: (a: string) => string;
}) {
  if (items.length === 0) return <span className="text-fg-muted">—</span>;
  return (
    <>
      {items.map((a, i) => (
        <span key={a} className={flagged && weak(a) ? "text-critical-fg font-medium" : undefined}>
          {i > 0 && ", "}{render(a)}
        </span>
      ))}
    </>
  );
}

function Flag({ on, children }: { on: boolean; children: ReactNode }) {
  return <span className={on ? "text-critical-fg font-medium" : undefined}>{children}</span>;
}

function ikeLabel(g: VpnGateway): string {
  const v = { ikev1: "IKEv1", ikev2: "IKEv2", "ikev2-preferred": "IKEv2 preferred" }[g.version] ?? g.version;
  return g.version === "ikev2" ? v : `${v} · ${g.exchange_mode} mode`;
}

/**
 * Site-to-site VPN tunnels and the crypto profiles they use, behind the vpn_* and ike_* rules.
 * A value turns red only when an active finding covers it.
 */
export function VpnSection({ vpn, findings }: { vpn: Vpn; findings: Finding[] }) {
  const active = new Set(findings.filter((f) => !f.dismissed).map((f) => f.finding_key));
  const has = (rule: string, key: string) => active.has(`${rule}:${key}`);
  const gateways = new Map(vpn.gateways.map((g) => [g.name, g]));
  const tunnelGateways = new Set(vpn.tunnels.flatMap((t) => t.gateways));
  const orphanGateways = vpn.gateways.filter((g) => !tunnelGateways.has(g.name));
  const profileFlagged = (kind: "ike" | "ipsec", name: string) =>
    ["vpn_weak_encryption", "vpn_weak_authentication", "vpn_weak_dh_group", "vpn_lifetime_long"]
      .some((r) => has(r, `${kind}:${name}`));

  const cryptoRows: ({ kind: "ike"; p: VpnIkeProfile } | { kind: "ipsec"; p: VpnIpsecProfile })[] = [
    ...vpn.ike_profiles.map((p) => ({ kind: "ike" as const, p })),
    ...vpn.ipsec_profiles.map((p) => ({ kind: "ipsec" as const, p })),
  ];

  return (
    <div className="flex flex-col gap-6">
      <div className="keep-together">
        <div className="text-[11px] font-semibold tracking-[0.08em] uppercase text-fg-muted mb-2">Tunnels</div>
        <table>
          <thead>
            <tr><th>Tunnel</th><th>Peer</th><th>IKE</th><th>IKE crypto</th><th>IPSec crypto</th><th>Tunnel monitor</th></tr>
          </thead>
          <tbody>
            {vpn.tunnels.map((t) => {
              const gws = t.gateways.map((n) => gateways.get(n)).filter((g): g is VpnGateway => !!g);
              const stale = has("vpn_stale_config", `tunnel:${t.name}`);
              return (
                <tr key={t.name} className={t.disabled ? "opacity-60" : undefined}>
                  <td className="font-medium">
                    {t.name}
                    {t.disabled && <Badge tone="neutral" className="ml-2">Disabled</Badge>}
                    {stale && !t.disabled && <Badge tone="neutral" className="ml-2">Unused</Badge>}
                    {has("vpn_anti_replay_disabled", t.name) && (
                      <div className="text-[12px] text-critical-fg font-normal">Anti-replay off</div>
                    )}
                  </td>
                  {t.type === "globalprotect-satellite" ? (
                    <td colSpan={5} className="text-fg-muted">GlobalProtect satellite tunnel</td>
                  ) : t.type === "manual-key" ? (
                    <>
                      <td className="text-fg-muted">—</td>
                      <td><Flag on={has("vpn_manual_key", t.name)}>Manual key</Flag></td>
                      <td className="text-fg-muted">—</td>
                      <td>
                        {t.manual && <Flag on={has("vpn_manual_key", t.name)}>
                          {[t.manual.encryption, t.manual.authentication].filter(Boolean).map((a) => alg(a!)).join(" / ")}
                        </Flag>}
                      </td>
                      <td className="text-fg-muted">—</td>
                    </>
                  ) : (
                    <>
                      <td>
                        {gws.length === 0 ? <span className="text-fg-muted">—</span> : gws.map((g) => (
                          <div key={g.name}>{g.peer ?? "—"} <span className="text-fg-muted text-[12px]">({g.name})</span></div>
                        ))}
                      </td>
                      <td>
                        {gws.map((g) => (
                          <div key={g.name}>
                            <Flag on={has("ike_aggressive_mode", g.name) || has("ike_v1_only", g.name)}>{ikeLabel(g)}</Flag>
                          </div>
                        ))}
                      </td>
                      <td>
                        {gws.flatMap((g) => g.ike_profiles).map((n) => (
                          <div key={n}><Flag on={profileFlagged("ike", n)}>{n}</Flag></div>
                        ))}
                      </td>
                      <td>{t.ipsec_profile && <Flag on={profileFlagged("ipsec", t.ipsec_profile)}>{t.ipsec_profile}</Flag>}</td>
                      <td>
                        {t.monitor
                          ? <span>{t.monitor_destination ?? "On"}</span>
                          : <Flag on={has("vpn_no_tunnel_monitor", t.name)}>Off</Flag>}
                      </td>
                    </>
                  )}
                </tr>
              );
            })}
            {orphanGateways.map((g) => (
              <tr key={`gw-${g.name}`} className="opacity-60">
                <td className="text-fg-muted">
                  No tunnel <Badge tone="neutral" className="ml-2">{g.disabled ? "Disabled" : "Unused"} gateway</Badge>
                </td>
                <td>{g.peer ?? "—"} <span className="text-fg-muted text-[12px]">({g.name})</span></td>
                <td>{ikeLabel(g)}</td>
                <td>{g.ike_profiles.join(", ")}</td>
                <td colSpan={2} className="text-fg-muted">—</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {cryptoRows.length > 0 && (
        <div className="keep-together">
          <div className="text-[11px] font-semibold tracking-[0.08em] uppercase text-fg-muted mb-2">Crypto profiles</div>
          <table>
            <thead>
              <tr><th>Profile</th><th>Encryption</th><th>Authentication</th><th>DH group</th><th>Key lifetime</th></tr>
            </thead>
            <tbody>
              {cryptoRows.map(({ kind, p }) => {
                const key = `${kind}:${p.name}`;
                const enc = p.encryption;
                const auth = kind === "ike" ? (p as VpnIkeProfile).hash : (p as VpnIpsecProfile).authentication;
                const allGcm = enc.length > 0 && enc.every((c) => c.endsWith("-gcm"));
                const dh = kind === "ike" ? (p as VpnIkeProfile).dh_groups : [(p as VpnIpsecProfile).dh_group];
                const ah = kind === "ipsec" && (p as VpnIpsecProfile).protocol === "ah";
                const used = kind === "ike"
                  ? vpn.gateways.some((g) => g.ike_profiles.includes(p.name))
                  : vpn.tunnels.some((t) => t.ipsec_profile === p.name);
                return (
                  <tr key={key} className={used ? undefined : "opacity-60"}>
                    <td className="font-medium">
                      <span className="text-fg-muted font-normal text-[12px] mr-1.5">{kind === "ike" ? "IKE" : "IPSec"}</span>
                      {p.name}
                      {p.built_in && <Badge tone="neutral" className="ml-2">Predefined</Badge>}
                      {!used && <Badge tone="neutral" className="ml-2">Not used</Badge>}
                    </td>
                    <td>
                      {ah ? <Flag on={has("vpn_weak_encryption", key)}>None (AH)</Flag>
                        : <Algs items={enc} weak={(a) => WEAK_CIPHERS.has(a)} flagged={has("vpn_weak_encryption", key)} />}
                    </td>
                    <td>
                      <Algs items={auth} flagged={has("vpn_weak_authentication", key)}
                        weak={(a) => WEAK_HASHES.has(a) || (NO_AUTH.has(a) && !allGcm)} />
                    </td>
                    <td>
                      <Algs items={dh} render={group} flagged={has("vpn_weak_dh_group", key)}
                        weak={(g) => g === "no-pfs" || Number(g.replace("group", "")) < 14} />
                    </td>
                    <td className={cn("tab-num", has("vpn_lifetime_long", key) && "text-critical-fg font-medium")}>
                      {hours(p.lifetime_hours)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
