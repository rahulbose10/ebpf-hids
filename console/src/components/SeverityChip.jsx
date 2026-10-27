// One severity chip for the whole console, so every page shows the same
// shape and colours. Full class strings are written out so Tailwind finds them.
const TONE = {
  critical: "border-critical/50 bg-critical/10 text-critical",
  high: "border-high/50 bg-high/10 text-high",
  medium: "border-medium/50 bg-medium/10 text-medium",
  low: "border-low/50 bg-low/10 text-low",
};

function SeverityChip({ severity }) {
  const level = String(severity || "low").toLowerCase();

  return (
    <span
      className={`inline-flex h-[18px] shrink-0 items-center rounded border px-1.5 font-mono text-[10px] leading-none ${
        TONE[level] || TONE.low
      }`}
    >
      {level}
    </span>
  );
}

export default SeverityChip;
