function GaugeBar({ fill = 0, mark = null, alarm = false }) {
  const totalBlocks = 64;
  const clamped = Math.min(Math.max(Number(fill) || 0, 0), 1);
  const activeBlocks = Math.round(clamped * totalBlocks);
  const markBlock = mark === null ? -1 : Math.min(Math.round(mark * totalBlocks), totalBlocks - 1);

  return (
    <div className="gauge-bar" role="img" aria-label={`anomaly gauge ${clamped.toFixed(2)}${alarm ? ", flagged" : ""}`}>
      {Array.from({ length: totalBlocks }, (_, i) => {
        let state = "inactive";
        if (i < activeBlocks) {
          state = alarm ? "hot" : "active";
        }
        const edge = i === markBlock ? " outline outline-1 outline-critical/70" : "";
        return <span key={i} className={`gauge-block ${state}${edge}`} />;
      })}
    </div>
  );
}

export default GaugeBar;
