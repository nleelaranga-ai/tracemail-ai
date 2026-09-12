/** @type {import('next').NextConfig} */

function sanitizeUrl(raw) {
  if (!raw) return "";
  let url = String(raw).trim().replace(/^["']|["']$/g, "").replace(/\/+$/, "");
  if (!url) return "";
  if (!url.startsWith("http://") && !url.startsWith("https://") && !url.startsWith("/")) {
    url = `https://${url}`;
  }
  return url;
}

const rawEnvUrl = process.env.NEXT_PUBLIC_API_URL || process.env.BACKEND_URL || "";
let backendUrl = sanitizeUrl(rawEnvUrl) || "https://tracemail-ai-production.up.railway.app";

let isValidBackend = false;
if (backendUrl.startsWith("http://") || backendUrl.startsWith("https://")) {
  try {
    const parsed = new URL(backendUrl);
    if (parsed.protocol === "http:" || parsed.protocol === "https:") {
      isValidBackend = true;
      backendUrl = parsed.origin + (parsed.pathname === "/" ? "" : parsed.pathname.replace(/\/+$/, ""));
    }
  } catch {
    isValidBackend = false;
  }
}

const nextConfig = {
  reactStrictMode: false,
  allowedDevOrigins: ["localhost", "127.0.0.1"],
  async rewrites() {
    if (!isValidBackend || !backendUrl) {
      return [];
    }

    return [
      {
        source: "/api/:path*",
        destination: `${backendUrl}/api/:path*`,
      },
      {
        source: "/health",
        destination: `${backendUrl}/health`,
      },
      {
        source: "/health/:path*",
        destination: `${backendUrl}/health/:path*`,
      },
    ];
  },
};

export default nextConfig;

