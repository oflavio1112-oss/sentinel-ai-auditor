import { createFileRoute } from "@tanstack/react-router";
import { ScanApp } from "@/components/scan-app";

export const Route = createFileRoute("/")({ component: Home });

function Home() {
  return <ScanApp />;
}
