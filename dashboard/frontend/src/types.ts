export type Severity = "CRITICAL" | "WARNING" | "LOW" | "INFORMATIONAL";

export interface SeverityCounts {
  CRITICAL: number;
  WARNING: number;
  LOW: number;
  INFORMATIONAL: number;
}

export interface ScoreBreakdownEntry {
  count: number;
  weight: number;
  points: number;
}

export interface Summary {
  severity_counts: SeverityCounts;
  score: number;
  score_breakdown: Record<Severity, ScoreBreakdownEntry>;
  weights: Record<Severity, number>;
  thresholds: { informational_max: number; low_max: number; warning_max: number };
  points_based_label: Severity;
  risk_label: Severity;
  floor_applied: boolean;
  total: number;
}

export interface ScoringSettings {
  weights: Record<Severity, number>;
  thresholds: { informational_max: number; low_max: number; warning_max: number };
  default_weights?: Record<Severity, number>;
  default_thresholds?: { informational_max: number; low_max: number; warning_max: number };
}

export interface AssessmentListItem {
  id: number;
  filename: string;
  hostname: string | null;
  source: string;
  uploaded_at: string;
  summary: Summary;
  panorama_managed: boolean;
  client_name: string | null;
  serial: string | null;
  model: string | null;
}

export interface Finding {
  rule_id: string;
  finding_key: string;
  title: string;
  category: string;
  severity: Severity;
  default_severity: Severity;
  severity_overridden: boolean;
  message: string;
  recommendation: string;
  /** "core" = the dashboard's own rules (labelled with the brand's rule-set name); "scm" = Palo Alto Strata Cloud Manager BPA results. */
  program: "core" | "scm";
  /** For core rules, what the rule is based on; SCM findings are always "scm". */
  source_type: "cis" | "pan_docs" | "custom" | "scm";
  source_ref: string | null;
  /** SCM BPA check numbers: the matching checks for a core rule, or the check itself for SCM. */
  scm_check_ids: number[];
  dismissed: boolean;
  rule_disabled: boolean;
  /** SCM finding for a check a core rule already flagged — listed but not scored twice. */
  duplicate_of?: string[];
  not_scored_reason?: "duplicate" | "scm_excluded" | null;
  location?: string | null;
  /** PAN-OS CLI commands that fix this finding, when the fix is mechanical. */
  cli?: FindingCli | null;
}

export interface CliChoice {
  key: string;
  label: string;
  /** Matching objects that exist in the config; empty when there are none or the value is free text. */
  options: string[];
  placeholder: string;
  free: boolean;
  /** Pre-filled value the engineer can edit (e.g. a recommended list of file types). */
  default?: string | null;
}

export interface FindingCli {
  commands: string[];
  choices: CliChoice[];
  note: string | null;
  order: number;
}

export type RuleScope = "shared_pre" | "device_group_pre" | "device_group_post" | "shared_post";

export interface SecurityRule {
  name: string;
  action: string;
  disabled: string;
  log_end: string;
  log_start: string;
  description: string;
  profile_group: string;
  indiv_profiles: Record<string, string[]>;
  from_zones: string[];
  to_zones: string[];
  sources: string[];
  destinations: string[];
  applications: string[];
  services: string[];
  tags: string[];
  log_setting?: string | null;
  rule_scope: RuleScope | null;
  /** On Panorama: the device group the rule comes from (null for Shared). */
  scope_name?: string | null;
}

export interface Zone {
  name: string;
  mode: string;
  zone_protection_profile: string | null;
  packet_buffer_protection?: boolean;
}

export interface AdminAccount {
  name: string;
  role: string;
  auth_profile: string;
}

export interface AvDecoder {
  action: string;
  wildfire_action: string;
  mlav_action: string;
}

export interface SeverityRule {
  name: string;
  severities: string[];
  action: string;
  packet_capture: string;
  host?: string;
}

export interface DnsCategorySetting {
  action: string;
  packet_capture: string;
}

export interface VulnerabilityException {
  id: string;
  action: string;
  exempt_ips: string[];
}

export interface ProfileRule {
  name: string;
  action?: string;
  direction: string;
  applications: string[];
  file_types: string[];
  analysis?: string;
}

// Fields present depend on the profile type (antivirus/spyware/vulnerability/
// url_filtering/wildfire_analysis/file_blocking) — see PROFILE_SETTINGS_PARSERS
// in the backend for which subset each type populates.
export interface ProfileSettings {
  decoders?: Record<string, AvDecoder>;
  packet_capture?: boolean;
  inline_ml?: Record<string, string>;
  // Antivirus: string[] of threat-exception IDs. Vulnerability Protection:
  // VulnerabilityException[] (id/action/exempt_ips) — same field name, two
  // shapes depending on ptype, matching the backend's per-type parsers.
  threat_exceptions?: string[] | VulnerabilityException[];
  severity_rules?: SeverityRule[];
  dns_sinkhole_enabled?: boolean;
  dns_categories?: Record<string, DnsCategorySetting>;
  whitelist?: { name: string; description: string }[];
  block_categories?: string[];
  alert_categories?: string[];
  credential_enforcement_mode?: string;
  credential_enforcement_block_categories?: string[];
  log_container_page_only?: boolean;
  local_inline_cat?: boolean;
  cloud_inline_cat?: boolean;
  rules?: ProfileRule[];
  // Anti-Spyware / Vulnerability Protection; absent on assessments parsed before it was captured
  inline_cloud_analysis?: { enabled: boolean; models: Record<string, string> };
}

export interface UnresolvedRule {
  rule: string;
  action: "allow" | "block";
  causes: { field: "destination" | "application" | "service"; kind: string; object: string | null }[];
}

export interface ReachResult {
  source_zone: string;
  status: "open" | "restricted" | "blocked" | "uncertain";
  // For "uncertain": the outcome if none of the unresolved rules actually match
  lean: "open" | "closed" | null;
  // Rule name that decided it, or "intrazone-default" / "interzone-default"
  via: string;
  specific_allows: string[];
  // Only rules that could flip the outcome
  unresolved_rules: UnresolvedRule[];
}

export interface MgmtExposureEntry {
  interface: string;
  profile: string;
  zone: string | null;
  permitted_ips: number;
  address_known: boolean;
  services: Record<string, ReachResult[]>;
}

export interface LicenseGate {
  status: "applies" | "no_license" | "license_unknown";
  reason: string;
}

export interface SecurityProfileEntry {
  name: string;
  rule_count: number;
  settings: ProfileSettings;
}

export interface ProfileGroup {
  name: string;
  members: Record<string, string[]>;
  rule_count: number;
}

export interface DecryptionRule {
  name: string;
  action: string;
  disabled: string;
  type: string;
  profile: string | null;
  rule_scope: RuleScope | null;
  /** On Panorama: the device group the rule comes from (null for Shared). */
  scope_name?: string | null;
}

export interface DecryptionProfile {
  name: string;
  min_version: string;
  min_version_explicit: boolean;
  // null = not set in the config (the schema declares no default)
  forward_proxy_block_expired: boolean | null;
  forward_proxy_block_untrusted: boolean | null;
  /** Absent on assessments stored before these were parsed. */
  no_proxy_block_expired?: boolean | null;
  no_proxy_block_untrusted?: boolean | null;
}

export interface ZoneProtectionProfile {
  name: string;
  flood: Record<string, boolean | null>;
  syn_action: string | null;
  scans: { id: string; action: string }[];
  packet_based?: Record<string, boolean>;
}

export interface InterfaceMgmtProfile {
  name: string;
  services: Record<string, boolean>;
  permitted_ip: string[];
  interfaces: string[];
}

export interface GpTlsProfile {
  name: string;
  found: boolean;
  min_version?: string;
  max_version?: string;
  weak_algorithms?: string[];
}

export interface GpAuthProfile {
  name: string;
  found: boolean;
  sequence?: boolean;
  method?: string;
  mfa?: boolean;
  external_mfa_capable?: boolean;
  lockout_attempts?: number;
  members?: GpAuthProfile[];
}

export interface GpCertProfile {
  name: string;
  found: boolean;
  use_crl?: boolean;
  use_ocsp?: boolean;
  block_expired?: boolean;
}

interface GpEndpoint {
  name: string;
  location: string;
  interface: string | null;
  tls: GpTlsProfile | null;
  auth_profiles: { name: string; os: string; profile: GpAuthProfile | null }[];
  certificate_profile: GpCertProfile | null;
}

export interface GpAgentConfig {
  name: string;
  connect_method: string;
  connect_method_set: boolean;
  enforce_globalprotect: boolean;
  user_override: string;
  override_timeout_min: number;
  collect_hip: boolean;
  internal_gateways: number;
  external_gateways: number;
  internal_host_detection: boolean;
  save_credentials: string;
  cookie_lifetime_hours: number | null;
}

export interface GpPortal extends GpEndpoint {
  root_ca: string[];
  agent_configs: GpAgentConfig[];
  satellite: { configured: boolean; root_ca: string[] };
}

export interface GpGateway extends GpEndpoint {
  tunnel_mode: boolean;
  client_configs: {
    name: string;
    access_routes: string[];
    exclude_routes: string[];
    ip_pool: string[];
    cookie_lifetime_hours: number | null;
  }[];
}

export interface MgmtPlane {
  idle_timeout_min: number | null;
  failed_attempts: number | null;
  lockout_minutes: number | null;
  api_key_lifetime_min: number | null;
  password_complexity: { enabled: boolean; minimum_length: number | null };
  snmp_polling: { version: string; default_community: boolean } | null;
  mgmt_tls: { profile: string; found: boolean; min_version?: string } | null;
  update_schedule: Record<string, { frequency: string; action: string | null; threshold_hours: number | null }>;
  log_forwarding: Record<"system" | "config", { name: string; filter: string; destinations: string[] }[]>;
  ldap: { name: string; ssl: string | null; verify_certificate: boolean }[];
  radius: { name: string; protocol: string | null }[];
  tacplus: { name: string; protocol: string }[];
  syslog: { name: string; servers: { name: string; server: string | null; transport: string }[] }[];
  snmptrap: { name: string; version: string | null; default_community: boolean }[];
}

export interface HaConfig {
  enabled: boolean;
  mode?: string;
  group_id?: string | null;
  peer_ip?: string | null;
  peer_ip_backup?: string | null;
  config_sync?: boolean;
  session_sync?: boolean;
  ha2_keep_alive?: boolean;
  heartbeat_backup?: boolean;
  preemptive?: boolean;
  timers?: string;
  passive_link_state?: string;
  session_owner?: string | null;
  ha1_port?: string | null;
  ha1_encryption?: boolean;
  ha1_backup_port?: string | null;
  ha2_port?: string | null;
  ha3_port?: string | null;
  link_monitoring?: { enabled: boolean; groups: { name: string; interfaces: string[]; failure_condition: string }[] };
  path_monitoring?: { enabled: boolean; groups: { type: string; name: string }[] };
}

export interface VpnIkeProfile {
  name: string;
  encryption: string[];
  hash: string[];
  dh_groups: string[];
  lifetime_hours: number;
  built_in?: boolean;
}

export interface VpnIpsecProfile {
  name: string;
  protocol: "esp" | "ah";
  encryption: string[];
  authentication: string[];
  dh_group: string;
  lifetime_hours: number;
  built_in?: boolean;
}

export interface VpnGateway {
  name: string;
  version: string;
  exchange_mode: string;
  ike_profiles: string[];
  peer: string | null;
  auth: string;
  disabled: boolean;
}

export interface VpnTunnel {
  name: string;
  type: "auto-key" | "manual-key" | "globalprotect-satellite";
  tunnel_interface: string | null;
  gateways: string[];
  ipsec_profile: string | null;
  anti_replay: boolean;
  monitor: boolean;
  monitor_destination: string | null;
  disabled: boolean;
  manual?: { protocol: string; encryption: string | null; authentication: string | null };
}

export interface Vpn {
  ike_profiles: VpnIkeProfile[];
  ipsec_profiles: VpnIpsecProfile[];
  gateways: VpnGateway[];
  tunnels: VpnTunnel[];
}

export interface DosRates { method: string; alarm: number; activate: number; max: number; default: boolean }

export interface DosProfile {
  name: string;
  type: "aggregate" | "classified";
  flood: Record<string, boolean>;
  rates: Record<string, DosRates | null>;
  session_limit: number | null;
}

export interface DosRule {
  name: string;
  scope: string | null;
  action: string;
  aggregate_profile: string | null;
  classified_profile: string | null;
  from: string[];
  to: string[];
  disabled: boolean;
}

export interface Certificate {
  name: string;
  scope: string;
  common_name: string | null;
  subject: string | null;
  issuer: string | null;
  ca: boolean;
  has_private_key: boolean;
  key_algorithm: string | null;
  key_bits: number | null;
  signature_hash: string | null;
  not_after: string | null;
  self_signed: boolean;
  used_by: string[];
  services: string[];
}

export interface Advisory {
  id: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL" | "NONE";
  score: number | null;
  date: string | null;
  fix: string;
  url: string;
}

export interface ShadowedRule {
  rule: string;
  position: number;
  action: string;
  by: string;
  by_position: number;
  by_action: string;
  vsys: string | null;
  kind: "redundant" | "block_allowed" | "allow_blocked";
}

export interface DynamicGroupUse {
  name: string;
  groups: { name: string; filter: string }[];
  tags: string[];
}

export interface NatRule {
  name: string;
  disabled: boolean;
  description: string;
  nat_type: string;
  from_zones: string[];
  to_zones: string[];
  to_interface: string;
  sources: string[];
  destinations: string[];
  service: string;
  source_translation: { type: string; translated: string[]; interface: string | null; bidirectional: boolean } | null;
  destination_translation: { type: string; address: string | null; port: string | null } | null;
  rule_scope: RuleScope | null;
  /** On Panorama: the device group the rule comes from (null for Shared). */
  scope_name?: string | null;
  vsys?: string | null;
}

export interface RemediationItem {
  key: string;
  order: number;
  title: string;
  summary: string;
  risk: string;
  severity: Severity;
  points: number;
  finding_count: number;
  finding_keys: string[];
  checks: { rule_id: string; title: string; severity: Severity; program: "core" | "scm"; count: number }[];
}

export interface RulebaseAnalysis {
  available: boolean;
  reason?: string;
  rule_count?: number;
  shadowed: ShadowedRule[];
  duplicates: { kind: "addresses" | "services"; value: string; names: string[] }[];
}

export interface AdvisoryReport {
  status: "ok" | "loading" | "error" | "disabled";
  fetched_at: string | null;
  count: number;
  reason: string | null;
  version: string | null;
  recommended: string | null;
  matches: Advisory[];
}

export interface AssessmentData {
  panorama_managed: boolean;
  /** Set when resolved from Panorama: what the assessment was built from. */
  panorama?: PanoramaResolution;
  device_group?: string | null;
  certificates?: { certificates: Certificate[] };
  nat_rules?: NatRule[];
  object_usage?: {
    available: boolean;
    unused: Record<string, string[]>;
    reason?: string;
    // Addresses counted as used only because an in-use dynamic address group names one of their tags.
    used_via_dynamic_group?: DynamicGroupUse[];
  };
  mgmt_plane?: MgmtPlane;
  ha_config?: HaConfig;
  vpn?: Vpn;
  dos?: { profiles: DosProfile[]; rules: DosRule[] };
  session_settings?: { rematch: boolean; tcp_forward_oo_queue: boolean };
  globalprotect?: { portals: GpPortal[]; gateways: GpGateway[] };
  // Absent on assessments stored before these were parsed.
  decryption?: { rules: DecryptionRule[]; profiles: DecryptionProfile[] };
  zone_protection_profiles?: ZoneProtectionProfile[];
  interface_mgmt_profiles?: InterfaceMgmtProfile[];
  system_info: Record<string, any>;
  licenses: { available: boolean; licenses: any[]; reason?: string };
  admin_accounts: AdminAccount[];
  zones: Zone[];
  security_rules: SecurityRule[];
  security_profiles: Record<string, SecurityProfileEntry[]>;
  profile_groups: ProfileGroup[];
  syslog_profiles: number;
  ha: Record<string, any>;
  management: Record<string, any>;
}

export interface AssessmentDetail {
  /** The same firewall's run just before this one, if any. */
  previous_run?: { id: number; uploaded_at: string; filename: string } | null;
  /** Why no CLI commands are offered (a Panorama-managed firewall's own export or tech support file). */
  cli_unavailable?: string | null;
  /** Parsed straight from Panorama's own config (an older upload of Panorama's tech support file): mixes
   *  every device group. */
  panorama_appliance?: boolean;
  id: number;
  filename: string;
  hostname: string | null;
  client_name: string | null;
  serial: string | null;
  model: string | null;
  source: string;
  uploaded_at: string;
  /** When the stored file was last re-parsed with the current parser, if ever. */
  reanalyzed_at?: string | null;
  data: AssessmentData;
  findings: Finding[];
  summary: Summary;
  license_gates: { inline_cloud_analysis: LicenseGate };
  // null for assessments parsed before these inputs were captured
  mgmt_exposure: MgmtExposureEntry[] | null;
  threat_intel?: ThreatIntelCoverage;
  advisories?: AdvisoryReport;
  rulebase?: RulebaseAnalysis;
  remediation?: RemediationItem[];
  scm_coverage?: ScmCoverage | null;
  scm: ScmStatus;
  notes?: Note[];
}

export type NoteKind = "finding" | "remediation" | "security_rule" | "nat_rule";

/** An analyst's note on one entry, numbered as an endnote in the report. */
export interface Note {
  id: number;
  number: number;
  target_kind: NoteKind;
  target_key: string;
  /** What the note is about, in words — kept even if the entry later disappears. */
  target_label: string;
  body: string;
  created_at: string;
  updated_at: string;
  /** Set when the note was copied forward from an earlier run of the same firewall. */
  carried_from?: { id: number; uploaded_at: string } | null;
}

export type ScmCoverageStatus = "core_missed" | "object_mismatch" | "no_rule" | "core_off" | "by_design" | "not_applicable" | "covered";

export interface ScmCoverage {
  checks: {
    check_id: number;
    title: string;
    category: string;
    severity: Severity;
    status: ScmCoverageStatus;
    objects: number;
    object_type: string | null;
    /** Failed objects the core rules deliberately skip (unused built-in profiles, HA settings with HA off). */
    not_applicable_objects?: number;
    /** For by_design: why the core rule skipped these objects on purpose. */
    reason?: string | null;
    points: number;
    core_rules: { id: string; title: string; enabled: boolean; findings: number }[];
    failed_fields: string[];
  }[];
  summary: Record<ScmCoverageStatus, { checks: number; points: number }>;
  text: string;
}

export interface ScmStatus {
  /** The server has SCM credentials (or an egress proxy that supplies them). */
  configured: boolean;
  /** The assessment's config was kept at upload, so it can be sent to SCM. */
  config_stored: boolean;
  platform: "ngfw" | "panorama" | null;
  include_in_score: boolean;
  run: {
    status: "completed" | "failed";
    ran_at: string;
    error: string | null;
    checks_evaluated: number;
    results_evaluated: number;
    failed: number;
    passed: number;
  } | null;
}

export interface ScmCheck {
  id: number;
  rule_id: string;
  name: string;
  severity: "Critical" | "High" | "Warning" | "Informational";
  section: string;
  object_type: string;
  object_type_label: string;
  category: string;
  description: string;
  default_severity: Severity;
  effective_severity: Severity;
  severity_override: Severity | null;
  enabled: boolean;
  /** Set for checks that start switched off, explaining why. */
  default_off_reason?: string | null;
  /** Core rules that check the same setting. */
  core_rules: string[];
}

export interface ScmCatalog {
  about: string;
  retrieved: string;
  checks: ScmCheck[];
  include_in_score: boolean;
  configured: boolean;
}

export interface PanoramaDeviceGroup {
  name: string;
  device_serials: string[];
  reference_templates: string[];
}

/** A firewall Panorama manages, as offered in the upload picker. */
export interface PanoramaDevice {
  serial: string;
  hostname: string | null;
  /** Its own device group; device_groups lists the whole chain, top of the hierarchy first. */
  device_group: string | null;
  device_groups: string[];
  template_stack: string | null;
  /** Templates in priority order (the first one wins). */
  templates: string[];
}

export interface PanoramaResolution {
  mode: "device" | "device_group";
  serial: string | null;
  device_groups: string[];
  template_stack: string | null;
  templates: string[];
  /** Whether the file recorded the device-group hierarchy (parent groups). */
  hierarchy_known: boolean;
}

export interface UploadResult {
  id: number;
  filename: string;
  hostname: string | null;
}

export interface PanoramaUploadResult {
  panorama_export: true;
  upload_id: number;
  filename: string;
  device_groups: PanoramaDeviceGroup[];
  devices?: PanoramaDevice[];
}

export interface RuleDef {
  id: string;
  title: string;
  category: string;
  default_severity: Severity;
  effective_severity: Severity;
  severity_override: Severity | null;
  program: "core";
  source_type: "cis" | "pan_docs" | "custom";
  source_ref: string | null;
  scm_check_ids: number[];
  description: string;
  default_thresholds: Record<string, number>;
  enabled: boolean;
  enabled_by_default?: boolean;
  /** Why the rule starts switched off, when it does. */
  default_off_reason?: string | null;
  threshold_overrides: Record<string, number> | null;
}

export interface ClientSummary {
  name: string;
  assessments: number;
}

export interface ThreatIntelCoverage {
  lists: { id: string; label: string; inbound: string[]; outbound: string[]; disabled_rules: string[] }[];
  quic: { rules: string[]; disabled_rules: string[]; decryption_in_use: boolean };
  objects_captured: boolean;
}

export interface CompareSide {
  id: number;
  filename: string;
  hostname: string | null;
  client_name: string | null;
  serial: string | null;
  model: string | null;
  uploaded_at: string;
  summary: AssessmentDetail["summary"];
  scm_run: boolean;
  points_by_program: { core: number; scm: number };
}

export interface CompareRuleDelta {
  rule_id: string;
  title: string;
  category: string;
  program: "core" | "scm";
  base_count: number;
  target_count: number;
  base_points: number;
  target_points: number;
}

export interface CompareResult {
  base: CompareSide;
  target: CompareSide;
  score_delta: number;
  by_rule: CompareRuleDelta[];
  new: Finding[];
  resolved: Finding[];
  changed: { finding: Finding; before: { severity: Severity; counted: boolean; dismissed: boolean };
             after: { severity: Severity; counted: boolean; dismissed: boolean } }[];
  notes: { kind: string; text: string }[];
}

export interface ReanalyzeResult {
  before: { score: number; total: number };
  after: { score: number; total: number };
  /** False for a tech support file uploaded before its CLI output was kept: system info, licenses
   * and HA status stay as first parsed. */
  full_source: boolean;
}
