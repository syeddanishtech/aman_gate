export type SectionId =
  | "overview"
  | "protect"
  | "firewall"
  | "bridge"
  | "assurance"
  | "evidence"
  | "settings"
  | "judge";

export interface NavTarget {
  section: SectionId;
  /** Optional sub-tab inside the section (protect: shield|registry · firewall: live|replay|policies|approvals). */
  sub?: string;
}
