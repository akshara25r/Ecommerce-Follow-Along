# eslint-disable

[![Travis build status](http://img.shields.io/travis/gajus/eslint-disable/master.svg?style=flat-square)](https://travis-ci.org/gajus/eslint-disable)
[![Coveralls](https://img.shields.io/coveralls/gajus/eslint-disable.svg?style=flat-square)](https://coveralls.io/github/gajus/eslint-disable)
[![NPM version](http://img.shields.io/npm/v/eslint-disable.svg?style=flat-square)](https://www.npmjs.org/package/eslint-disable)
[![Canonical Code Style](https://img.shields.io/badge/code%20style-canonical-blue.svg?style=flat-square)](https://github.com/gajus/canonical)
[![Twitter Follow](https://img.shields.io/twitter/follow/kuizinas.svg?style=social&label=Follow)](https://twitter.com/kuizinas)

Disables ESLint plugins.

## Motivation

Sometimes you may need to disable an entire ESLint plugin, e.g. for performance reasons.

## API

```js
import {
  extractConfig,
  disablePlugins,
} from 'eslint-disable';

/**
 * @param eslintConfig ESLint base configuration. This configuration may extend from other configurations.
 * @returns ESLint configuration with resolved extends directives.
 */
extractConfig(
  eslintConfig,
);

/**
 * @param Object eslintConfig ESLint base configuration.
 * @param string[] Plugin names.
 * @returns Object ESLint configuration with matching plugins and rules disabled.
 */
disablePlugins(
  eslintConfig,
  pluginNames,
);

```

## Usage

In your `.eslintrc.js`:

```js
const {
  extractConfig,
  disablePlugins,
} = require('eslint-disable');

const baseConfig = {
  'extends': [
    'canonical'
  ],
  'root': true,
};

// This will disable "import" plugin and all rules matching "import/*" pattern.
module.exports = disablePlugins(
  extractConfig(
    baseConfig,
  ),
  [
    'import',
  ]
);

```

## ESLint Issue

Native ESLint support has been proposed on several occasions. However, thus far it has been ignored.

* https://github.com/eslint/eslint/issues/14026
