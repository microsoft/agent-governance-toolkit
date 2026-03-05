// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
const path = require('path');
const CopyPlugin = require('copy-webpack-plugin');
const HtmlWebpackPlugin = require('html-webpack-plugin');

module.exports = {
  entry: {
    popup: './src/popup/index.tsx',
    options: './src/options/index.tsx',
    background: './src/background/service-worker.ts',
    'content/github': './src/content/github.ts',
    'content/jira': './src/content/jira.ts',
    'content/aws': './src/content/aws.ts',
  },
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: '[name].js',
    clean: true,
  },
  module: {
    rules: [
      {
        test: /\.tsx?$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
      {
        test: /\.css$/,
        use: ['style-loader', 'css-loader'],
      },
    ],
  },
  resolve: {
    extensions: ['.tsx', '.ts', '.js'],
    alias: {
      '@': path.resolve(__dirname, 'src'),
    },
  },
  plugins: [
    new CopyPlugin({
      patterns: [
        { from: 'manifest.json', to: 'manifest.json' },
        { from: 'icons', to: 'icons' },
        // Keep legacy files during migration
        { from: 'devtools', to: 'devtools' },
      ],
    }),
    new HtmlWebpackPlugin({
      template: './src/popup/popup.html',
      filename: 'popup.html',
      chunks: ['popup'],
    }),
    new HtmlWebpackPlugin({
      template: './src/options/options.html',
      filename: 'options.html',
      chunks: ['options'],
    }),
  ],
  optimization: {
    splitChunks: {
      chunks: (chunk) => {
        // Don't split background or content scripts
        return !['background', 'content/github', 'content/jira', 'content/aws'].includes(chunk.name);
      },
    },
  },
};
