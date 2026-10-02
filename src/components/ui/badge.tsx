import type { HTMLAttributes } from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs font-medium tracking-wide",
  {
    variants: {
      tone: {
        default: "border-border bg-surface-2 text-muted",
        accent: "border-border bg-accent/10 text-fg",
        critical: "border-critical/30 bg-critical/10 text-critical",
        high: "border-high/30 bg-high/10 text-high",
        medium: "border-medium/30 bg-medium/10 text-medium",
        low: "border-low/30 bg-low/10 text-low",
        info: "border-info/30 bg-info/10 text-info",
      },
    },
    defaultVariants: { tone: "default" },
  },
);

export function Badge({
  className,
  tone,
  ...props
}: HTMLAttributes<HTMLSpanElement> & VariantProps<typeof badgeVariants>) {
  return <span className={cn(badgeVariants({ tone }), className)} {...props} />;
}
