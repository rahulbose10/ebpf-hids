function GaugeBar({ score = 0 }) {

  const totalBlocks = 64;

  const activeBlocks = Math.round(score * totalBlocks);

  return (

    <div className="gauge-bar">

      {Array.from({ length: totalBlocks }, (_, i) => (

        <span
          key={i}
          className={
            i < activeBlocks
              ? "gauge-block active"
              : "gauge-block inactive"
          }
        />

      ))}

    </div>

  );

}

export default GaugeBar;