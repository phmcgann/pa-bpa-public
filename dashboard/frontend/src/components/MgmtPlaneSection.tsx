import type { ReactNode } from "react";
import type { Finding, MgmtPlane } from "../types";

const TLS_LABEL: Record<string, string> = { "tls1-0": "TLSv1.0", "tls1-1": "TLSv1.1", "tls1-2": "TLSv1.2", "tls1-3": "TLSv1.3" };
const UPDATE_LABEL: Record<string, string> = { "anti-virus": "Antivirus updates", threats: "Apps & threats updates", wildfire: "WildFire updates" };

function Row({ label, children, flagged }: { label: string; children: ReactNode; flagged: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-4 py-2 border-b border-divider last:border-b-0 text-[13px]">
      <span className="text-fg-muted shrink-0">{label}</span>
      <span className={flagged ? "font-medium text-critical-fg text-right" : "font-medium text-fg text-right"}>{children}</span>
    </div>
  );
}

function Group({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div>
      <div className="text-[11px] font-semibold tracking-[0.08em] uppercase text-fg-muted mb-1">{title}</div>
      {children}
    </div>
  );
}

function minutes(n: number): string {
  if (n % 1440 === 0) return `${n / 1440} day${n === 1440 ? "" : "s"}`;
  if (n % 60 === 0) return `${n / 60} hour${n === 60 ? "" : "s"}`;
  return `${n} min`;
}

/**
 * Management-plane settings behind the admin_*, snmp_*, *_logs_* and content-update rules.
 * A value turns red only when an active finding covers it.
 */
export function MgmtPlaneSection({ mp, findings }: { mp: MgmtPlane; findings: Finding[] }) {
  const active = new Set(findings.filter((f) => !f.dismissed).map((f) => f.finding_key));
  const has = (rule: string, key = "global") => active.has(`${rule}:${key}`);
  const attempts = mp.failed_attempts ?? 0;
  const lockout = mp.lockout_minutes ?? 0;
  const idle = mp.idle_timeout_min ?? 60;
  const sys = mp.log_forwarding.system.flatMap((m) => m.destinations);
  const cfg = mp.log_forwarding.config.flatMap((m) => m.destinations);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-x-8 gap-y-4">
      <Group title="Administrator sign-in">
        <Row label="Failed attempts before lockout" flagged={has("admin_lockout_weak", "failed_attempts")}>
          {attempts === 0 ? "Never locks" : attempts}
        </Row>
        <Row label="Lockout time" flagged={has("admin_lockout_weak", "lockout_time")}>
          {attempts === 0 ? "—" : lockout === 0 ? "Until unlocked by an admin" : minutes(lockout)}
        </Row>
        <Row label="Idle timeout" flagged={has("admin_idle_timeout_long")}>
          {idle === 0 ? "Never" : minutes(idle)}{mp.idle_timeout_min == null && " (default)"}
        </Row>
        <Row label="API key lifetime" flagged={has("api_key_no_lifetime")}>
          {mp.api_key_lifetime_min ? minutes(mp.api_key_lifetime_min) : "Never expires"}
        </Row>
        <Row label="Password complexity" flagged={has("password_complexity_weak")}>
          {mp.password_complexity.enabled ? `On · min ${mp.password_complexity.minimum_length ?? 8} characters` : "Off"}
        </Row>
        <Row label="Web interface TLS" flagged={has("mgmt_tls_below_1_2")}>
          {mp.mgmt_tls ? `${mp.mgmt_tls.profile}${mp.mgmt_tls.min_version ? ` · ${TLS_LABEL[mp.mgmt_tls.min_version] ?? mp.mgmt_tls.min_version}+` : ""}` : "PAN-OS default"}
        </Row>
        {mp.ldap.map((p) => (
          <Row key={`ldap-${p.name}`} label={`LDAP · ${p.name}`} flagged={has("ldap_profile_no_tls", p.name)}>
            {p.ssl === "no" ? "No TLS" : p.verify_certificate ? "TLS, certificate verified" : "Certificate not verified"}
          </Row>
        ))}
        {mp.radius.map((p) => (
          <Row key={`radius-${p.name}`} label={`RADIUS · ${p.name}`} flagged={has("radius_weak_protocol", p.name)}>
            {p.protocol ?? "Not set"}
          </Row>
        ))}
        {mp.tacplus.map((p) => (
          <Row key={`tacplus-${p.name}`} label={`TACACS+ · ${p.name}`} flagged={has("tacacs_pap", p.name)}>{p.protocol}</Row>
        ))}
      </Group>

      <Group title="Monitoring & updates">
        <Row label="System log forwarding" flagged={has("system_logs_not_forwarded")}>
          {sys.length ? sys.join(", ") : "Not forwarded"}
        </Row>
        <Row label="Configuration log forwarding" flagged={has("config_logs_not_forwarded")}>
          {cfg.length ? cfg.join(", ") : "Not forwarded"}
        </Row>
        {mp.syslog.map((p) => (
          <Row key={`syslog-${p.name}`} label={`Syslog · ${p.name}`} flagged={has("syslog_not_tls", p.name)}>
            {p.servers.map((s) => s.transport).join(", ") || "No servers"}
          </Row>
        ))}
        <Row label="SNMP polling" flagged={has("snmp_v2c", "polling")}>
          {mp.snmp_polling ? `${mp.snmp_polling.version}${mp.snmp_polling.default_community ? " · community 'public'" : ""}` : "Not configured"}
        </Row>
        {mp.snmptrap.map((t) => (
          <Row key={`trap-${t.name}`} label={`SNMP traps · ${t.name}`} flagged={has("snmp_v2c", `trap:${t.name}`)}>
            {t.version ?? "—"}{t.default_community ? " · community 'public'" : ""}
          </Row>
        ))}
        {Object.entries(UPDATE_LABEL).map(([type, label]) => {
          const u = mp.update_schedule[type];
          return (
            <Row key={type} label={label} flagged={has("content_updates_not_timely", type)}>
              {u ? `${u.frequency.replace(/-/g, " ")}${u.action && u.frequency !== "real-time" ? ` · ${u.action.replace(/-/g, " ")}` : ""}` : "No schedule"}
            </Row>
          );
        })}
      </Group>
    </div>
  );
}
