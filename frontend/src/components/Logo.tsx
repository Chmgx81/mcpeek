export default function Logo({ size = 20, className = "" }: { size?: number; className?: string }) {
  return (
    <img
      src="/logo.svg"
      alt="MCPeek"
      width={size}
      height={size}
      className={className}
    />
  );
}
