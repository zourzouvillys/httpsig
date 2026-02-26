import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

const config: Config = {
  title: 'httpsig',
  tagline: 'HTTP Message Signatures for every platform',
  favicon: 'img/favicon.ico',

  future: {
    v4: true,
  },

  url: 'https://zourzouvillys.github.io',
  baseUrl: '/httpsig/',

  organizationName: 'zourzouvillys',
  projectName: 'httpsig',
  trailingSlash: false,

  onBrokenLinks: 'throw',

  markdown: {
    hooks: {
      onBrokenMarkdownLinks: 'warn',
    },
  },

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          editUrl:
            'https://github.com/zourzouvillys/httpsig/tree/main/docs/',
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    colorMode: {
      defaultMode: 'light',
      disableSwitch: false,
      respectPrefersColorScheme: true,
    },
    navbar: {
      title: 'httpsig',
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'docsSidebar',
          position: 'left',
          label: 'Docs',
        },
        {
          href: 'https://github.com/zourzouvillys/httpsig',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Documentation',
          items: [
            {
              label: 'Getting Started',
              to: '/docs/getting-started/go',
            },
            {
              label: 'Concepts',
              to: '/docs/concepts/how-it-works',
            },
            {
              label: 'Guides',
              to: '/docs/guides/signing',
            },
          ],
        },
        {
          title: 'More',
          items: [
            {
              label: 'GitHub',
              href: 'https://github.com/zourzouvillys/httpsig',
            },
            {
              label: 'RFC 9421',
              href: 'https://www.rfc-editor.org/rfc/rfc9421',
            },
          ],
        },
      ],
      copyright: `Copyright ${new Date().getFullYear()} httpsig contributors. Apache License 2.0.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['java', 'kotlin', 'swift', 'bash', 'json'],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
