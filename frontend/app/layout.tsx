import type { Metadata } from "next";
import "../styles/globals.css";
import { Providers } from "./providers";

export const metadata: Metadata = {
  title: "TraceMail AI",
  description: "Trace. Analyze. Investigate. Protect."
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-bg font-body text-ink antialiased">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
