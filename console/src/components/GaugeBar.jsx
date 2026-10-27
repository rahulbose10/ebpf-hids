// A row of blocks that fills left to right with the anomaly score (0 to 1).
// Blocks past the alert threshold turn red, so the threshold is visible
// without reading a number.
function GaugeBar({ score = 0, threshold = 0.85 }) {
  const totalBlocks = 64;
  const clamped = Math.min(Math.max(Number(score) || 0, 0), 1);
  const activeBlocks = Math.round(clamped * totalBlocks);

  return (
    <div className="gauge-bar" role="img" aria-label={`anomaly score ${clamped}`}>
      {Array.from({ length: totalBlocks }, (_, i) => {
        const filled = i < activeBlocks;
        const overThreshold = (i + 1) / totalBlocks > threshold;

        let state = "inactive";
        if (filled) {
          state = overThreshold ? "hot" : "active";
        }

        return <span key={i} className={`gauge-block ${state}`} />;
      })}
    </div>
  );
}

export default GaugeBar;
