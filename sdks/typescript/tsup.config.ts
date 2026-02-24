import { defineConfig } from 'tsup';

export default defineConfig([
  // ESM build — external dependencies resolve natively
  {
    entry: {
      index: 'src/index.ts',
      'middleware/index': 'src/middleware/index.ts',
    },
    format: ['esm'],
    dts: true,
    sourcemap: true,
    clean: true,
    splitting: false,
    treeshake: true,
  },
  // CJS build — bundle cborg (ESM-only) into the output
  {
    entry: {
      index: 'src/index.ts',
      'middleware/index': 'src/middleware/index.ts',
    },
    format: ['cjs'],
    dts: true,
    sourcemap: true,
    splitting: false,
    treeshake: true,
    noExternal: ['cborg'],
  },
]);
