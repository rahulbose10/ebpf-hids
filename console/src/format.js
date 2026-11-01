export function formatKts(ts) {
  return typeof ts === "number" ? ts.toFixed(3) : "-";
}

export function formatEvent(event) {
  if (event == null) return "-";
  if (typeof event !== "object") return String(event);
  return [event.type, event.detail].filter(Boolean).join(" ") || "-";
}
