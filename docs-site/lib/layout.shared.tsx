import type { BaseLayoutProps } from 'fumadocs-ui/layouts/shared';
import { appName, gitConfig } from './shared';

export function baseOptions(): BaseLayoutProps {
  return {
    nav: {
      title: (
        <span className="font-bold tracking-tight">
          <span className="text-foreground">PI</span>
          <span className="text-muted-foreground"> Platform</span>
        </span>
      ),
    },
    githubUrl: `https://github.com/${gitConfig.user}/${gitConfig.repo}`,
    links: [
      {
        text: 'Docs',
        url: '/docs',
        active: 'nested-url',
      },
      {
        text: 'Roadmap',
        url: '/docs/roadmap',
        active: 'nested-url',
      },
    ],
  };
}
