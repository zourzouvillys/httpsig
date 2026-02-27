import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

const sidebars: SidebarsConfig = {
  docsSidebar: [
    'intro',
    {
      type: 'category',
      label: 'Getting Started',
      items: [
        'getting-started/go',
        'getting-started/typescript',
        'getting-started/java',
        'getting-started/swift',
        'getting-started/kotlin',
      ],
    },
    {
      type: 'category',
      label: 'Concepts',
      items: [
        'concepts/how-it-works',
        'concepts/components',
        'concepts/algorithms',
        'concepts/key-management',
        'concepts/content-digest',
      ],
    },
    {
      type: 'category',
      label: 'Guides',
      items: [
        'guides/signing',
        'guides/verifying',
        'guides/integrations',
        'guides/proxy-forwarding',
      ],
    },
  ],
};

export default sidebars;
