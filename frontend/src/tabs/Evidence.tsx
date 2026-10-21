import { PageHeader } from "../components/common";
import Audit from "./Audit";

/** Evidence & Research = the AMAN 1.0 Audit & Evidence tab (real HMAC-chained audit, real metrics). */
export default function Evidence({ refreshKey }: { refreshKey: number }) {
  return (
    <div>
      <PageHeader
        eyebrow="Audit · metrics · reproducible evidence"
        title="Evidence & Research"
        subtitle="Tamper-evident audit chain, advisory classifier metrics and the exportable evidence report. All values are computed from persisted backend events."
      />
      <Audit refreshKey={refreshKey} />
    </div>
  );
}
