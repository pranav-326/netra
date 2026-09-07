/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    return [
      {
        source: '/api/ingest/:path*',
        destination: 'http://127.0.0.1:8000/api/v1/ingest/:path*',
      },
      {
        source: '/api/gateway/:path*',
        destination: 'http://127.0.0.1:8080/api/v1/:path*',
      },
    ];
  },
};

module.exports = nextConfig;
