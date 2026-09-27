import type { ReactNode } from "react";
import type { Finding, HaConfig } from "../types";

function Row({ label, children, flagged }: { label: string; children: ReactNode; flagged?: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-4 py-2 border-b border-divider last:border-b-0 text-[13px]">
      <span className="text-fg-muted shrink-0">{label}</span>
      <span className={flagged ? "font-medium text-critical-fg text-right" : "font-medium text-fg text-right"}>{children}</span>
    </div>
  );
}

const onOff = (v: boolean | undefined) => (v ? "On" : "Off");
const MODE: Record<string, string> = { "active-passive": "Active/passive", "active-active": "Active/active" };
const TIMERS: Record<string, string> = { recommended: "Recommended", aggressive: "Aggressive", advanced: "Advanced" };
const OWNER: Record<string, string> = { "first-packet": "First packet", "primary-device": "Primary device" };

/**
 * HA settings from the config, behind the ha_* rules. A value turns red only when an active
 * finding covers it.
 */
export function HaConfigRows({ ha, findings }: { ha: HaConfig; findings: Finding[] }) {
  const active = new Set(findings.filter((f) => !f.dismissed).map((f) => f.finding_key));
  const has = (rule: string, key = "global") => active.has(`${rule}:${key}`);
  if (!ha.enabled) return <Row label="Configured">Not enabled</Row>;

  const aa = ha.mode === "active-active";
  const links = (ha.link_monitoring?.groups ?? []).filter((g) => g.interfaces.length);
  const paths = ha.path_monitoring?.groups ?? [];
  const monitoringFlagged = has("ha_no_monitoring");
  const linkText = ha.link_monitoring?.enabled === false ? "Off"
    : links.length ? `${links.length} group${links.length === 1 ? "" : "s"} · ${links.reduce((n, g) => n + g.interfaces.length, 0)} interfaces`
    : "No groups";
  const pathText = ha.path_monitoring?.enabled === false ? "Off"
    : paths.length ? `${paths.length} group${paths.length === 1 ? "" : "s"}` : "No groups";

  return (
    <div className="ha-rows">
      <Row label="Mode">{MODE[ha.mode ?? ""] ?? ha.mode}{ha.group_id && ` · group ${ha.group_id}`}</Row>
      <Row label="HA1 control link">{ha.ha1_port ?? "Default port"}{ha.peer_ip && ` → ${ha.peer_ip}`}</Row>
      <Row label="HA1 backup" flagged={has("ha1_no_backup")}>
        {ha.peer_ip_backup ? `${ha.ha1_backup_port ?? "Configured"} → ${ha.peer_ip_backup}` : "None"}
      </Row>
      <Row label="HA1 encryption" flagged={has("ha1_encryption_disabled")}>{onOff(ha.ha1_encryption)}</Row>
      <Row label="Heartbeat backup" flagged={has("ha_heartbeat_backup_off")}>
        {onOff(ha.heartbeat_backup)}
        {!ha.heartbeat_backup && ha.ha1_port === "management" && " · not needed"}
      </Row>
      <Row label="Config sync" flagged={has("ha_config_sync_disabled")}>{onOff(ha.config_sync)}</Row>
      <Row label="Session sync" flagged={has("ha_session_sync_disabled")}>{onOff(ha.session_sync)}</Row>
      <Row label="HA2 keep-alive" flagged={has("ha2_keepalive_disabled")}>{onOff(ha.ha2_keep_alive)}</Row>
      {aa ? (
        <>
          <Row label="HA3 link" flagged={has("ha_active_active_incomplete", "ha3")}>{ha.ha3_port ?? "None"}</Row>
          <Row label="Session owner" flagged={has("ha_active_active_incomplete", "session_owner")}>
            {OWNER[ha.session_owner ?? ""] ?? ha.session_owner ?? "Not set"}
          </Row>
        </>
      ) : (
        <Row label="Passive link state" flagged={has("ha_passive_link_state_shutdown")}>
          {ha.passive_link_state === "auto" ? "Auto" : "Shutdown"}
        </Row>
      )}
      <Row label="Link monitoring" flagged={monitoringFlagged}>{linkText}</Row>
      <Row label="Path monitoring" flagged={monitoringFlagged}>{pathText}</Row>
      <Row label="Timers">{TIMERS[ha.timers ?? ""] ?? ha.timers}</Row>
    </div>
  );
}
