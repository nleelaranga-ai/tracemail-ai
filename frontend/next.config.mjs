/** @type {import('next').NextConfig} */
const backendUrl = (process.env.NEXT_PUBLIC_API_URL || "")
  .trim()
  .replace(/\/+$/, "");

const nextConfig = {
  reactStrictMode: false,
  allowedDevOrigins: ["localhost", "127.0.0.1"],
  async rewrites() {
    if (!backendUrl.startsWith("https://")) {
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
    ];
  },
};

export default nextConfig;

