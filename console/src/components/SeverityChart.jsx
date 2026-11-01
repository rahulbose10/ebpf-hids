import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
} from "recharts";

function SeverityChart({ alerts }) {

  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };

  alerts.forEach((alert) => {

    const level = String(alert.severity).toLowerCase();

    if (counts[level] !== undefined) {

      counts[level]++;

    }

  });

  const data = [
    { name: "Critical", value: counts.critical },
    { name: "High", value: counts.high },
    { name: "Medium", value: counts.medium },
    { name: "Low", value: counts.low },
  ];

  return (

    <ResponsiveContainer
      width="100%"
      height={250}
    >

      <BarChart data={data}>

        <XAxis dataKey="name" />

        <YAxis />

        <Tooltip />

        <Bar
          dataKey="value"
        />

      </BarChart>

    </ResponsiveContainer>

  );

}

export default SeverityChart;