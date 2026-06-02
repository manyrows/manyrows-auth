import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'

// need this wrapper otherwise the grid is not loaded correctly because of the manyrows-admin global variable. There
// https://github.com/vitejs/vite/issues/16443
function createIifeWrapper(): Plugin {
  return {
    name: 'wrap-all-in-iife',
    apply: 'build',
    enforce: 'post',
    generateBundle(_options, bundle) {
      // @ts-ignore
      for (const file of Object.values(bundle)) {
        if (file.type === 'chunk' && file.fileName === 'appkit/assets/appkit.js') {
          file.code = `(function(){${file.code}})();`;
        }
      }
    },
  };
}

// Inline CSS into JS so the IIFE bundle is fully self-contained (no separate .css file needed)
function inlineCssPlugin(): Plugin {
  return {
    name: 'inline-css-into-js',
    apply: 'build',
    enforce: 'post',
    generateBundle(_options, bundle) {
      // Find the CSS asset
      let cssCode = '';
      const cssFiles: string[] = [];
      for (const [fileName, file] of Object.entries(bundle)) {
        if (file.type === 'asset' && fileName.endsWith('.css') && typeof file.source === 'string') {
          cssCode += file.source;
          cssFiles.push(fileName);
        }
      }
      if (!cssCode) return;

      // Remove CSS assets from bundle
      for (const f of cssFiles) {
        delete bundle[f];
      }

      // Inject CSS loader into the JS chunk
      const escaped = cssCode.replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$/g, '\\$');
      const injector = `(function(){var s=document.getElementById("ak-styles");if(!s){s=document.createElement("style");s.id="ak-styles";s.textContent=\`${escaped}\`;document.head.appendChild(s)}})();`;

      for (const file of Object.values(bundle)) {
        if (file.type === 'chunk' && file.fileName === 'appkit/assets/appkit.js') {
          file.code = injector + file.code;
          break;
        }
      }
    },
  };
}

// https://vite.dev/config/
export default defineConfig({
  server: {
    port: 5174
  },
  plugins: [react(), inlineCssPlugin(), createIifeWrapper()],
  esbuild: {
    drop: ['console', 'debugger']
  },
  build: {
    emptyOutDir: true,
    assetsDir:"appkit/assets",
    sourcemap: false,
    cssMinify: true,
    minify: 'esbuild',
    rollupOptions: {
      treeshake: true,
      output: {
        entryFileNames: `appkit/assets/appkit.js`,
        chunkFileNames: `appkit/assets/appkit.js`,
        assetFileNames: `appkit/assets/appkit.[ext]`
      }
    },
  }
})
