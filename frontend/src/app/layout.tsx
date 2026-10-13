import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "CoreWorks Hub",
  description: "Centralni portal za IT alate i integracije.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="sr"><body>{children}</body></html>;
}
