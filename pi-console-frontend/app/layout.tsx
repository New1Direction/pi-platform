import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PI Console",
  description: "Human Interface Layer for the PI Platform",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen antialiased">{children}</body>
    </html>
  );
}
