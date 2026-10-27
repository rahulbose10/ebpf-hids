// ts from the sensor is kernel monotonic seconds since boot.
// The shared contract forbids turning it into a wall clock time,
// so every page shows it as a plain number.
export function formatKts(ts) {
  return typeof ts === "number" ? ts.toFixed(3) : "-";
}
