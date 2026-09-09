/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: false,
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || ""
  },
  allowedDevOrigins: ["localhost", "127.0.0.1"]
};

export default nextConfig;