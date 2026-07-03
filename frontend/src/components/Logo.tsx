import Image from "next/image";

export default function Logo({ size = 20, className = "" }: { size?: number; className?: string }) {
  return (
    <Image
      src="/logo.svg"
      alt="MCPeek"
      width={size}
      height={size}
      className={className}
      priority
    />
  );
}
