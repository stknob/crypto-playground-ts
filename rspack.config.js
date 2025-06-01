const path = require('path');

module.exports = {
  entry: {
    index: './index.mts',
  },
  target: [ 'node', 'es2022', ],
  output: {
    clean: true,
    filename: '[name].mjs',
    path: path.resolve(__dirname, 'dist'),
  },
  experiments: {
    outputModule: true,
  },
  module: {
    rules: [{
        test: /\.[mc]?ts$/,
        type: 'javascript/auto',
        loader: 'builtin:swc-loader',
        options: {
          jsc: {
            parser: {
              syntax: 'typescript',
            },
          },
        },
    }],
  },
  resolve: {
    extensionAlias: {
      '.js': ['.ts', '.js'],
      '.cjs': ['.cts', '.cjs'],
      '.mjs': ['.mts', '.mjs'],
    },
  },
};
