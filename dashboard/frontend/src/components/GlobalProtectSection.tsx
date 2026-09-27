import { ArrowRight } from "lucide-react";
import type { ReactNode } from "react";
import type { Finding, GpAgentConfig, GpAuthProfile, GpCertProfile, GpGateway, GpPortal, GpTlsProfile } from "../types";
import { cn } from "../lib/cn";
import { SectionCard } from "./SectionCard";
import { Badge } from "./ui/Badge";
import { Button } from "./ui/Button";
import { SeverityIcon } from "./ui/SeverityIcon";
import { Stat } from "./ui/Stat";

const TLS_LABEL: Record<string, string> = {
  sslv3: "SSLv3", "tls1-0": "TLSv1.0", "tls1-1": "TLSv1.1", "tls1-2": "TLSv1.2", "tls1-3": "TLSv1.3", max: "Max",
};
const METHOD_LABEL: Record<string, string> = {
  "local-database": "Local database", ldap: "LDAP", radius: "RADIUS", tacplus: "TACACS+", "saml-idp": "SAML",
  kerberos: "Kerberos", cloud: "Cloud Identity Engine", sequence: "Sequence", none: "None",
};
const CONNECT_LABEL: Record<string, string> = {
  "user-logon": "User-logon (Always On)", "pre-logon": "Pre-logon (Always On)", "on-demand": "On-demand",
  "pre-logon-then-on-demand": "Pre-logon then On-demand",
};
const OVERRIDE_LABEL: Record<string, string> = {
  allowed: "Allow", "with-comment": "Allow with comment", "with-passcode": "Allow with passcode",
  "with-ticket": "Allow with ticket", disabled: "Disallow",
};

const AGENT_CONFIG_RULES = [
  "gp_connect_on_demand", "gp_not_enforced", "gp_user_can_disable", "gp_hip_collection_disabled",
  "gp_no_internal_host_detection",
];

/** Active (not dismissed) GlobalProtect findings, with lookups by exact key or key prefix. */
function useGpFindings(findings: Finding[]) {
  const active = findings.filter((f) => f.rule_id.startsWith("gp_") && !f.dismissed);
  return {
    active,
    has: (ruleId: string, key: string) => active.some((f) => f.finding_key === `${ruleId}:${key}`),
    forObject: (match: (f: Finding) => boolean) => active.filter(match),
  };
}

function Bad({ children, on }: { children: ReactNode; on: boolean }) {
  return <span className={on ? "text-critical-fg font-medium" : undefined}>{children}</span>;
}

function Muted({ children }: { children: ReactNode }) {
  return <span className="text-fg-muted">{children}</span>;
}

function Issues({ items }: { items: Finding[] }) {
  if (items.length === 0) return <span className="text-good-fg">No issues</span>;
  return (
    <ul className="m-0 p-0 list-none flex flex-col gap-1">
      {items.map((f) => (
        <li key={f.finding_key} className="flex gap-1.5 leading-4">
          <SeverityIcon severity={f.severity} size={12} className="mt-0.5 shrink-0" />
          <span>{f.title}</span>
        </li>
      ))}
    </ul>
  );
}

function Tls({ tls, weakVersion, weakAlgos }: { tls: GpTlsProfile | null; weakVersion: boolean; weakAlgos: boolean }) {
  if (!tls) return <Muted>None</Muted>;
  if (!tls.found) return <Muted>'{tls.name}' (not in this file)</Muted>;
  return (
    <div className="leading-5">
      <div className="text-fg-2">{tls.name}</div>
      <Bad on={weakVersion}>{TLS_LABEL[tls.min_version!] ?? tls.min_version} – {TLS_LABEL[tls.max_version!] ?? tls.max_version}</Bad>
      {!!tls.weak_algorithms?.length && <div><Bad on={weakAlgos}>Allows {tls.weak_algorithms.join(", ")}</Bad></div>}
    </div>
  );
}

function authStrength(p: GpAuthProfile | null): "mfa" | "external" | "password" | "unknown" {
  if (!p || !p.found) return "unknown";
  if (p.sequence) {
    const parts = (p.members ?? []).map(authStrength);
    return parts.length && parts.every((s) => s === "mfa" || s === "external") ? "external" : "password";
  }
  return p.mfa ? "mfa" : p.external_mfa_capable ? "external" : "password";
}

function Login({ auth, cert, singleFactor }: {
  auth: { name: string; os: string; profile: GpAuthProfile | null }[];
  cert: GpCertProfile | null;
  singleFactor: boolean;
}) {
  if (auth.length === 0 && !cert) return <Muted>None</Muted>;
  return (
    <div className="flex flex-col gap-1 leading-5">
      {auth.map((a) => {
        const p = a.profile;
        const strength = authStrength(p);
        return (
          <div key={a.name} className="flex flex-wrap items-center gap-1.5">
            <span className="text-fg-2">{p?.name ?? "—"}</span>
            {p?.found && <Muted>{METHOD_LABEL[p.method ?? "none"] ?? p.method}</Muted>}
            {a.os !== "Any" && <Muted>· {a.os}</Muted>}
            {strength === "mfa" && <Badge tone="good">MFA</Badge>}
            {strength === "external" && <Badge tone="neutral" title="SAML/RADIUS/CIE can enforce MFA at the identity provider">MFA at IdP</Badge>}
            {strength === "password" && !cert && <Badge tone={singleFactor ? "critical" : "neutral"}>Password only</Badge>}
            {p && !p.found && <Muted>(not in this file)</Muted>}
          </div>
        );
      })}
      {cert && <div className="flex items-center gap-1.5"><Muted>+ certificate</Muted><span className="text-fg-2">{cert.name}</span></div>}
    </div>
  );
}

function ClientCert({ cert, flagged }: { cert: GpCertProfile | null; flagged: boolean }) {
  if (!cert) return <Muted>None</Muted>;
  if (!cert.found) return <Muted>'{cert.name}' (not in this file)</Muted>;
  const checks = [cert.use_ocsp && "OCSP", cert.use_crl && "CRL"].filter(Boolean).join(" + ");
  return (
    <div className="leading-5">
      <div className="text-fg-2">{cert.name}</div>
      <Bad on={flagged}>{checks ? `Revocation: ${checks}` : "No revocation check"}</Bad>
    </div>
  );
}

function hours(h: number | null): string {
  if (h == null) return "Not accepted";
  const n = h >= 24 ? +(h / 24).toFixed(1) : +h.toFixed(1);
  return `${n} ${h >= 24 ? "day" : "hour"}${n === 1 ? "" : "s"}`;
}

function AgentRow({ portal, cfg, has, issues }: {
  portal: GpPortal; cfg: GpAgentConfig; has: (rule: string, key: string) => boolean; issues: Finding[];
}) {
  const key = `${portal.name}:${cfg.name}`;
  const alwaysOn = cfg.connect_method === "user-logon" || cfg.connect_method === "pre-logon";
  const override = OVERRIDE_LABEL[cfg.user_override] ?? cfg.user_override;
  return (
    <tr>
      <td className="pl-5">
        <div className="font-medium text-fg">{cfg.name}</div>
        <div className="text-[11px] text-fg-muted">Portal {portal.name}</div>
      </td>
      <td>
        <Bad on={has("gp_connect_on_demand", key)}>{CONNECT_LABEL[cfg.connect_method] ?? cfg.connect_method}</Bad>
        {!cfg.connect_method_set && <div className="text-[11px] text-fg-muted">PAN-OS default</div>}
      </td>
      <td><Bad on={has("gp_not_enforced", key)}>{cfg.enforce_globalprotect ? "Yes" : "No"}</Bad></td>
      <td>
        <Bad on={has("gp_user_can_disable", key)}>{alwaysOn ? override : <Muted>n/a (on-demand)</Muted>}</Bad>
        {alwaysOn && cfg.override_timeout_min > 0 && <div className="text-[11px] text-fg-muted">re-enables after {cfg.override_timeout_min} min</div>}
      </td>
      <td><Bad on={has("gp_hip_collection_disabled", key)}>{cfg.collect_hip ? "Yes" : "No"}</Bad></td>
      <td>
        <div className="text-fg-2">{cfg.external_gateways} ext · {cfg.internal_gateways} int</div>
        <Bad on={has("gp_no_internal_host_detection", key)}>
          {cfg.internal_host_detection ? "Host detection on" : cfg.internal_gateways ? "No host detection" : ""}
        </Bad>
      </td>
      <td><Bad on={has("gp_long_cookie_lifetime", `portal:${key}`)}>{hours(cfg.cookie_lifetime_hours)}</Bad></td>
      <td className="pr-5 text-[12px]"><Issues items={issues} /></td>
    </tr>
  );
}

/**
 * GlobalProtect portals, their agent (app) configurations, and gateways, with the SSL/TLS,
 * authentication and certificate profiles they reference. A value turns red only when an active
 * core finding covers it, so dismissals and Settings changes are reflected here too.
 */
export function GlobalProtectSection({ portals, gateways, findings, onShowFindings }: {
  portals: GpPortal[];
  gateways: GpGateway[];
  findings: Finding[];
  onShowFindings: () => void;
}) {
  const { active, has, forObject } = useGpFindings(findings);
  const configs = portals.flatMap((p) => p.agent_configs.map((c) => ({ portal: p, cfg: c })));
  const endpointRules = ["gp_tls_below_1_2", "gp_tls_weak_ciphers", "gp_single_factor_auth", "gp_cert_profile_no_revocation"];

  const portalIssues = (p: GpPortal) => forObject((f) =>
    endpointRules.some((r) => f.finding_key === `${r}:portal:${p.name}`) ||
    ["gp_no_trusted_root_ca", "gp_satellite_no_root_ca"].some((r) => f.finding_key === `${r}:${p.name}`));
  const configIssues = (p: GpPortal, c: GpAgentConfig) => forObject((f) =>
    AGENT_CONFIG_RULES.some((r) => f.finding_key === `${r}:${p.name}:${c.name}`) ||
    f.finding_key === `gp_long_cookie_lifetime:portal:${p.name}:${c.name}`);
  const gatewayIssues = (g: GpGateway) => forObject((f) =>
    endpointRules.some((r) => f.finding_key === `${r}:gateway:${g.name}`) ||
    g.client_configs.some((c) => f.finding_key === `gp_split_tunnel:${g.name}:${c.name}`
      || f.finding_key === `gp_long_cookie_lifetime:gateway:${g.name}:${c.name}`));

  return (
    <>
      <div className="grid grid-cols-2 lg:grid-cols-4 print:grid-cols-4 gap-3">
        <Stat label="Portals" value={portals.length} sub={portals.map((p) => p.name).join(", ") || "None"} />
        <Stat label="Gateways" value={gateways.length} sub={gateways.map((g) => g.name).join(", ") || "None"} />
        <Stat label="Agent configurations" value={configs.length} sub="app settings pushed by portals" />
        <Stat
          label="GlobalProtect findings"
          value={active.length}
          sub={active.length ? "open in Findings →" : "nothing to fix"}
          onClick={active.length ? onShowFindings : undefined}
        />
      </div>

      {portals.length > 0 && (
        <SectionCard title="Portals" note="Where users log in and download their app configuration." bare>
          <div className="table-scroll -mx-5">
            <table className="gp-table min-w-[860px]">
              <thead>
                <tr>
                  <th className="pl-5">Portal</th><th>Server TLS</th><th>Login</th><th>Client certificate</th>
                  <th>Trusted root CA</th><th className="pr-5 w-[220px]">Issues</th>
                </tr>
              </thead>
              <tbody>
                {portals.map((p) => (
                  <tr key={p.name}>
                    <td className="pl-5">
                      <div className="font-medium text-fg">{p.name}</div>
                      <div className="text-[11px] text-fg-muted">{[p.interface, p.location].filter(Boolean).join(" · ")}</div>
                    </td>
                    <td><Tls tls={p.tls} weakVersion={has("gp_tls_below_1_2", `portal:${p.name}`)} weakAlgos={has("gp_tls_weak_ciphers", `portal:${p.name}`)} /></td>
                    <td><Login auth={p.auth_profiles} cert={p.certificate_profile} singleFactor={has("gp_single_factor_auth", `portal:${p.name}`)} /></td>
                    <td><ClientCert cert={p.certificate_profile} flagged={has("gp_cert_profile_no_revocation", `portal:${p.name}`)} /></td>
                    <td>
                      {p.root_ca.length ? <span className="text-fg-2">{p.root_ca.join(", ")}</span>
                        : <Bad on={has("gp_no_trusted_root_ca", p.name)}>None</Bad>}
                      {p.satellite.configured && (
                        <div className="text-[11px] text-fg-muted">
                          Satellites: {p.satellite.root_ca.length ? p.satellite.root_ca.join(", ")
                            : <Bad on={has("gp_satellite_no_root_ca", p.name)}>no root CA</Bad>}
                        </div>
                      )}
                    </td>
                    <td className="pr-5 text-[12px]"><Issues items={portalIssues(p)} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </SectionCard>
      )}

      {configs.length > 0 && (
        <SectionCard
          title="Agent configurations"
          note="The app settings each portal pushes to endpoints. Blank settings show the PAN-OS default."
          bare
        >
          <div className="table-scroll -mx-5">
            <table className="gp-table min-w-[980px]">
              <thead>
                <tr>
                  <th className="pl-5">Configuration</th><th>Connect method</th><th>Enforced for network access</th>
                  <th>User can disable</th><th>Collect HIP</th><th>Gateways</th><th>Auth cookie</th>
                  <th className="pr-5 w-[200px]">Issues</th>
                </tr>
              </thead>
              <tbody>
                {configs.map(({ portal, cfg }) => (
                  <AgentRow key={`${portal.name}:${cfg.name}`} portal={portal} cfg={cfg} has={has} issues={configIssues(portal, cfg)} />
                ))}
              </tbody>
            </table>
          </div>
        </SectionCard>
      )}

      {gateways.length > 0 && (
        <SectionCard title="Gateways" note="Where the VPN tunnel terminates and traffic is inspected." bare>
          <div className="table-scroll -mx-5">
            <table className="gp-table min-w-[860px]">
              <thead>
                <tr>
                  <th className="pl-5">Gateway</th><th>Server TLS</th><th>Login</th><th>Client certificate</th>
                  <th>Tunnel</th><th className="pr-5 w-[220px]">Issues</th>
                </tr>
              </thead>
              <tbody>
                {gateways.map((g) => (
                  <tr key={g.name}>
                    <td className="pl-5">
                      <div className="font-medium text-fg">{g.name}</div>
                      <div className="text-[11px] text-fg-muted">{[g.interface, g.location].filter(Boolean).join(" · ")}</div>
                    </td>
                    <td><Tls tls={g.tls} weakVersion={has("gp_tls_below_1_2", `gateway:${g.name}`)} weakAlgos={has("gp_tls_weak_ciphers", `gateway:${g.name}`)} /></td>
                    <td><Login auth={g.auth_profiles} cert={g.certificate_profile} singleFactor={has("gp_single_factor_auth", `gateway:${g.name}`)} /></td>
                    <td><ClientCert cert={g.certificate_profile} flagged={has("gp_cert_profile_no_revocation", `gateway:${g.name}`)} /></td>
                    <td>
                      {!g.tunnel_mode && <Muted>Tunnel mode off</Muted>}
                      {g.tunnel_mode && g.client_configs.length === 0 && <Muted>No client settings</Muted>}
                      <div className="flex flex-col gap-1 leading-5">
                        {g.client_configs.map((c) => {
                          const split = has("gp_split_tunnel", `${g.name}:${c.name}`);
                          const full = c.access_routes.length === 0 || c.access_routes.some((r) => r === "0.0.0.0/0" || r === "::/0");
                          return (
                            <div key={c.name}>
                              <span className="text-fg-2">{c.name}: </span>
                              <Bad on={split}>{full ? "Full tunnel" : `Split — ${c.access_routes.slice(0, 3).join(", ")}${c.access_routes.length > 3 ? ` +${c.access_routes.length - 3}` : ""}`}</Bad>
                              {c.exclude_routes.length > 0 && <Muted> · excludes {c.exclude_routes.length}</Muted>}
                              {c.cookie_lifetime_hours != null && (
                                <span className={cn("text-[11px] ml-1", has("gp_long_cookie_lifetime", `gateway:${g.name}:${c.name}`) ? "text-critical-fg" : "text-fg-muted")}>
                                  · cookie {hours(c.cookie_lifetime_hours)}
                                </span>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    </td>
                    <td className="pr-5 text-[12px]"><Issues items={gatewayIssues(g)} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </SectionCard>
      )}

      <div className="no-print">
        <Button variant="ghost" onClick={onShowFindings} className="-ml-2 text-left h-auto min-h-8 py-1">
          <span className="whitespace-normal">All GlobalProtect findings, including authentication lockout</span>
          <ArrowRight size={14} />
        </Button>
      </div>
    </>
  );
}
