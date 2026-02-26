import type {ReactNode} from 'react';
import Link from '@docusaurus/Link';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';

const languages = [
  {
    name: 'Go',
    install: 'go get github.com/zourzouvillys/httpsig/golang',
    link: '/docs/getting-started/go',
  },
  {
    name: 'TypeScript',
    install: 'npm install @zourzouvillys/httpsig',
    link: '/docs/getting-started/typescript',
  },
  {
    name: 'Java',
    install: 'com.zourzouvillys:httpsig',
    link: '/docs/getting-started/java',
  },
  {
    name: 'Swift',
    install: '.package(url: "...httpsig", from: "0.1.0")',
    link: '/docs/getting-started/swift',
  },
  {
    name: 'Kotlin',
    install: 'com.zourzouvillys:httpsig-kotlin',
    link: '/docs/getting-started/kotlin',
  },
];

const features = [
  {
    title: 'RFC 9421 Compliant',
    description:
      'Full implementation of HTTP Message Signatures. Signing, verification, signature base construction, and all standard derived components.',
  },
  {
    title: 'Five Languages, One API',
    description:
      'Consistent abstractions across Go, TypeScript, Java, Swift, and Kotlin. Shared test vectors guarantee interoperability.',
  },
  {
    title: 'Hardware-Backed Keys',
    description:
      'HSM and PKCS#11 support in Go and Java. Secure Enclave on Apple platforms. Android Keystore in Kotlin. Web Crypto API in TypeScript.',
  },
  {
    title: 'HTTP Client Integrations',
    description:
      'Drop-in middleware for net/http, fetch, axios, OkHttp, URLSession, Alamofire, Ktor, JDK HttpClient, and Spring WebClient.',
  },
];

function HeroSection(): ReactNode {
  return (
    <div className="hero-section">
      <div className="container">
        <Heading as="h1">HTTP Message Signatures for every platform</Heading>
        <p>
          A multi-language library implementing RFC 9421. Sign and verify HTTP
          requests and responses with RSA-PSS, ECDSA, Ed25519, or HMAC.
        </p>
        <div style={{display: 'flex', gap: '1rem', justifyContent: 'center'}}>
          <Link className="button button--primary button--lg" to="/docs/intro">
            Get Started
          </Link>
          <Link
            className="button button--outline button--lg"
            to="/docs/concepts/how-it-works">
            How It Works
          </Link>
        </div>
      </div>
    </div>
  );
}

function LanguageGrid(): ReactNode {
  return (
    <div className="container">
      <div className="language-grid">
        {languages.map((lang) => (
          <Link key={lang.name} to={lang.link} style={{textDecoration: 'none', color: 'inherit'}}>
            <div className="language-card">
              <h3>{lang.name}</h3>
              <code>{lang.install}</code>
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}

function FeaturesSection(): ReactNode {
  return (
    <div className="container features-section">
      <div className="features-grid">
        {features.map((feature) => (
          <div key={feature.title} className="feature-item">
            <h3>{feature.title}</h3>
            <p>{feature.description}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function Home(): ReactNode {
  return (
    <Layout
      title="HTTP Message Signatures"
      description="Multi-language HTTP Message Signatures (RFC 9421) library for Go, TypeScript, Java, Swift, and Kotlin.">
      <HeroSection />
      <LanguageGrid />
      <FeaturesSection />
    </Layout>
  );
}
