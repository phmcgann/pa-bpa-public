import type { ReactNode } from "react";
import type { AssessmentData, Finding } from "../types";
import { Badge } from "./ui/Badge";

const FLOOD_LABEL: Record<string, string> = {
  "tcp-syn": "SYN", udp: "UDP", icmp: "ICMP", icmpv6: "ICMPv6", "other-ip": "Other IP",
};

function Flag({ on, children }: { on: boolean; children: ReactNode }) {
  return <span className={on ? "text-critical-fg font-medium" : undefined}>{children}</span>;
}

function Heading({ children }: { children: ReactNode }) {
  return <div className="text-[11px] font-semibold tracking-[0.08em] uppercase text-fg-muted mb-2">{children}</div>;
}

function Row({ label, children, flagged }: { label: string; children: ReactNode; flagged: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-4 py-2 border-b border-divider last:border-b-0 text-[13px]">
      <span className="text-fg-muted">{label}</span>
      <Flag on={flagged}>{children}</Flag>
    </div>
  );
}

/**
 * DoS Protection policy and profiles, zone Packet Buffer Protection and global session settings,
 * behind the dos_*, zone_packet_buffer_*, session_* and tcp_* rules. Red only where a finding applies.
 */
export function DosSection({ data, findings }: { data: AssessmentData; findings: Finding[] }) {
  const active = new Set(findings.filter((f) => !f.dismissed).map((f) => f.finding_key));
  const has = (rule: string, key = "global") => active.has(`${rule}:${key}`);
  const dos = data.dos!;
  const session = data.session_settings;
  const pbpOff = data.zones.filter((z) => z.packet_buffer_protection === false).map((z) => z.name);

  return (
    <div className="flex flex-col gap-6">
      <div className="keep-together">
        <Heading>DoS Protection policy</Heading>
        {dos.rules.length === 0 ? (
          <p className="text-[13px] m-0"><Flag on={has("dos_no_protection")}>No DoS Protection rules.</Flag></p>
        ) : (
          <table>
            <thead><tr><th>Rule</th><th>From → to</th><th>Action</th><th>Profile</th></tr></thead>
            <tbody>
              {dos.rules.map((r) => {
                const flagged = has("dos_rule_not_protect", r.name);
                const profiles = [r.classified_profile && `${r.classified_profile} (classified)`,
                  r.aggregate_profile && `${r.aggregate_profile} (aggregate)`].filter(Boolean);
                return (
                  <tr key={`${r.scope}:${r.name}`} className={r.disabled ? "opacity-60" : undefined}>
                    <td className="font-medium">
                      {r.name}{r.disabled && <Badge tone="neutral" className="ml-2">Disabled</Badge>}
                    </td>
                    <td className="text-fg-2">{r.from.join(", ") || "any"} → {r.to.join(", ") || "any"}</td>
                    <td><Flag on={flagged && r.action !== "protect"}>{r.action.charAt(0).toUpperCase() + r.action.slice(1)}</Flag></td>
                    <td>{profiles.length ? profiles.join(", ") : <Flag on={flagged}>None</Flag>}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {dos.profiles.length > 0 && (
        <div className="keep-together">
          <Heading>DoS Protection profiles</Heading>
          <table>
            <thead><tr><th>Profile</th><th>Type</th><th>Flood protection</th><th>Thresholds</th><th>Session limit</th></tr></thead>
            <tbody>
              {dos.profiles.map((p) => {
                const incomplete = has("dos_profile_flood_incomplete", p.name);
                return (
                  <tr key={p.name}>
                    <td className="font-medium">{p.name}</td>
                    <td className="text-fg-2 capitalize">{p.type}</td>
                    <td>
                      {Object.entries(p.flood).map(([t, on], i) => (
                        <span key={t} className={!on ? (incomplete ? "text-critical-fg font-medium" : "text-fg-muted line-through") : undefined}>
                          {i > 0 && ", "}{FLOOD_LABEL[t] ?? t}
                        </span>
                      ))}
                    </td>
                    <td>
                      <Flag on={has("dos_profile_default_thresholds", p.name)}>
                        {Object.values(p.rates).some((r) => r && !r.default) ? "Tuned" : Object.keys(p.rates).length ? "Pre-filled defaults" : "—"}
                      </Flag>
                    </td>
                    <td className="tab-num">{p.session_limit != null ? p.session_limit.toLocaleString() : <span className="text-fg-muted">Off</span>}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-x-8 keep-together">
        <div>
          <Heading>Session settings</Heading>
          {session && (
            <>
              <Row label="Rematch sessions after policy changes" flagged={has("session_rematch_disabled")}>
                {session.rematch ? "On" : "Off"}
              </Row>
              <Row label="Forward segments past TCP out-of-order queue" flagged={has("tcp_forward_oo_queue")}>
                {session.tcp_forward_oo_queue ? "On" : "Off"}
              </Row>
            </>
          )}
          <Row label="Zone Packet Buffer Protection" flagged={pbpOff.length > 0}>
            {pbpOff.length ? `Off on ${pbpOff.join(", ")}` : "On for all zones"}
          </Row>
        </div>
      </div>
    </div>
  );
}
