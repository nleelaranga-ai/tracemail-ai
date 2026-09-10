/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: false,
  allowedDevOrigins: ["localhost", "127.0.0.1"],
  async rewrites() {
    const backendUrl = (process.env.NEXT_PUBLIC_API_URL || process.env.BACKEND_URL || "").trim().replace(/\/+$/, "");
    if (!backendUrl || backendUrl === "/") {
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
