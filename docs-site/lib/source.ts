import { loader } from 'fumadocs-core/source';
import { resolveFiles } from 'fumadocs-mdx';
import { docs } from 'collections/index';

// fumadocs-mdx 11.x returns `files` as a lazy function; fumadocs-core 15.x expects
// a plain array. Call resolveFiles() directly to get the eager array while
// preserving the typed Source shape via assertion.
const _typedSource = docs.toFumadocsSource();

export const source = loader({
  baseUrl: '/docs',
  source: {
    ..._typedSource,
    files: resolveFiles({ docs: docs.docs, meta: docs.meta }),
  } as typeof _typedSource,
});
