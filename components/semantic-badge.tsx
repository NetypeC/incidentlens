import { Badge } from "@/components/ui/badge";

export type SemanticBadgeKind =
  | "status"
  | "severity"
  | "source"
  | "correlation-confidence"
  | "ai-confidence"
  | "priority";

export function SemanticBadge({
  kind,
  value,
}: {
  kind: SemanticBadgeKind;
  value: string;
}) {
  return (
    <Badge
      className="status-tag"
      data-kind={kind}
      data-status={value.toLowerCase()}
    >
      <span className="status-tag__dot" aria-hidden="true" />
      {value}
    </Badge>
  );
}
