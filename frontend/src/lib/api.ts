export type User = {
  id: number;
  username: string;
  role: string;
};

export const TOKEN_KEY = "coreworks_access_token";

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(TOKEN_KEY);
}

export async function apiFetch(path: string, init: RequestInit = {}) {
  const token = getToken();
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (init.body) headers.set("Content-Type", "application/json");
  if (token) headers.set("Authorization", `Bearer ${token}`);
  return fetch(`/api${path}`, { ...init, headers, cache: "no-store" });
}

export async function readError(response: Response): Promise<string> {
  try {
    const data = await response.json();
    return typeof data.detail === "string" ? data.detail : "Zahtev nije uspeo.";
  } catch {
    return "Server trenutno nije dostupan.";
  }
}
