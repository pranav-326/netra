import './globals.css';
import { ThemeProvider } from '@/context/ThemeContext';
import Navbar from '@/components/layout/Navbar';
import Footer from '@/components/layout/Footer';

// The mark, inlined as a data URI so the tab icon needs no extra request and stays
// crisp at every density. Brand blue #0F3BB0 on transparent.
const FAVICON =
  "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='296 261 663 523'%3E%3Cmask id='m'%3E%3Crect x='296' y='261' width='663' height='523' fill='%23fff'/%3E%3Cpath d='M488 265H768V515L628 585L488 515Z' fill='%23000'/%3E%3C/mask%3E%3Cg stroke='%230F3BB0' stroke-width='46' fill='none'%3E%3Cpath d='M325 370V760H930V370L628 610Z' mask='url(%23m)'/%3E%3Cpath d='M508 285V505L628 565L748 505V285Z'/%3E%3C/g%3E%3Cg fill='%230F3BB0'%3E%3Ccircle cx='600' cy='386' r='26'/%3E%3Ccircle cx='658' cy='386' r='26'/%3E%3C/g%3E%3C/svg%3E";

export const metadata = {
  title: 'नेTRA — Email Threat Intelligence & Forensic Platform',
  description:
    'Deterministic email threat analysis: MIME forensics, sender authentication, live IP reputation, and Neo4j campaign correlation across a 7-stage pipeline.',
  applicationName: 'Netra',
  icons: {
    icon: [{ url: FAVICON, type: 'image/svg+xml' }],
    apple: '/netra-logo.jpeg',
  },
  openGraph: {
    title: 'नेTRA — Email Threat Intelligence & Forensic Platform',
    description:
      'Deterministic email threat analysis with auditable scoring and campaign correlation.',
    images: ['/netra-logo.jpeg'],
    type: 'website',
  },
};

export const viewport = {
  themeColor: [
    { media: '(prefers-color-scheme: light)', color: '#f4f6f8' },
    { media: '(prefers-color-scheme: dark)', color: '#0c1017' },
  ],
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="antialiased min-h-screen flex flex-col selection:bg-brand-600 selection:text-white">
        <ThemeProvider>
          <a
            href="#main"
            className="sr-only focus:not-sr-only focus:absolute focus:top-3 focus:left-3 focus:z-[60] focus:px-4 focus:py-2 focus:rounded-lg focus:bg-brand-600 focus:text-white focus:text-sm focus:font-semibold"
          >
            Skip to content
          </a>
          <Navbar />
          <main id="main" className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
            {children}
          </main>
          <Footer />
        </ThemeProvider>
      </body>
    </html>
  );
}
