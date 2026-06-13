import clsx from "clsx";
import type { ReactNode } from "react";

export function CodeBlock({
  code,
  className,
  maxHeight = "max-h-80",
}: {
  code?: string | null;
  className?: string;
  maxHeight?: string;
}) {
  if (!code) return null;
  return (
    <pre
      className={clsx(
        "overflow-auto rounded-lg border border-line bg-surface-0 p-3 font-mono text-xs leading-relaxed text-slate-300",
        maxHeight,
        className,
      )}
    >
      <code>{code}</code>
    </pre>
  );
}

export function InlineCode({ children }: { children: ReactNode }) {
  return (
    <code className="break-all rounded bg-surface-3 px-1.5 py-0.5 font-mono text-[12px] text-slate-200">
      {children}
    </code>
  );
}
