import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "CoreWorks Hub",
  description: "Central hub for IT tools and integrations.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
