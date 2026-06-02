export default function Spinner({
  size = 24,
  white = false,
}: {
  size?: number;
  white?: boolean;
}) {
  return (
    <span
      className={`ak-spinner${white ? " ak-spinner-white" : ""}`}
      style={{ width: size, height: size }}
      role="status"
      aria-label="Loading"
    />
  );
}
