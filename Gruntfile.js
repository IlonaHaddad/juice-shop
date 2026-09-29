/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

'use strict'

module.exports = function (grunt) {
  const os = grunt.option('os') || process.env.PCKG_OS_NAME || ''
  const platform = grunt.option('platform') || process.env.PCKG_CPU_ARCH || ''
  const node = grunt.option('node') || process.env.nodejs_version || process.env.PCKG_NODE_VERSION || ''

  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),

    replace_json: {
      manifest: {
        src: 'package.json',
        changes: {
          'engines.node': (node || '<%= pkg.engines.node %>'),
          os: (os ? [os] : '<%= pkg.os %>'),
          cpu: (platform ? [platform] : '<%= pkg.cpu %>')
        }
      }
    },

    compress: {
      pckg: {
        options: {
          mode: os === 'linux' ? 'tgz' : 'zip',
          archive: 'dist/<%= pkg.name %>-<%= pkg.version %>' + (node ? ('_node' + node) : '') + (os ? ('_' + os) : '') + (platform ? ('_' + platform) : '') + (os === 'linux' ? '.tgz' : '.zip')
        },
        files: [
          {
            src: [
              '.well-known/**',
              'LICENSE',
              '*.md',
              'package.json',
              'ctf.key',
              'swagger.yml',
              'server.ts',
              'config.schema.yml',
              'build/**',
              '!build/reports/**',
              'bom.json',
              'bom.xml',
              'config/*.yml',
              'data/*.ts',
              'data/static/**',
              'data/chatbot/.gitkeep',
              'encryptionkeys/**',
              'frontend/dist/frontend/**',
              'frontend/dist/bom/**',
              'frontend/src/**/*.ts',
              'ftp/**',
              'i18n/.gitkeep',
              'lib/**',
              'models/*.ts',
              'node_modules/**',
              'routes/*.ts',
              'uploads/complaints/.gitkeep',
              'views/**'
            ],
            dest: 'juice-shop_<%= pkg.version %>/'
          }
        ]
      }
    }
  })

  grunt.registerTask('checksum', 'Create .md5 checksum files', function () {
    const fs = require('node:fs')
    const crypto = require('node:crypto')
    fs.readdirSync('dist/').forEach(file => {
      const buffer = fs.readFileSync('dist/' + file)
      const md5 = crypto.createHash('md5')
      md5.update(buffer)
      const md5Hash = md5.digest('hex')
      const md5FileName = 'dist/' + file + '.md5'
      grunt.file.write(md5FileName, md5Hash)
      grunt.log.write(`Checksum ${md5Hash} written to file ${md5FileName}.`).verbose.write('...').ok()
      grunt.log.writeln()
    })
  })

  grunt.loadNpmTasks('grunt-replace-json')
  grunt.loadNpmTasks('grunt-contrib-compress')
  grunt.registerTask('package', ['replace_json:manifest', 'compress:pckg', 'checksum'])
}
const express = require('express')
const fs = require('fs')
const { exec } = require('child_process')
const sqlite3 = require('sqlite3').verbose()
const axios = require('axios')

const router = express.Router()
const db = new sqlite3.Database('data/juiceshop.sqlite')

// SQL Injection
router.get('/unsafe-user', (req, res) => {
  const email = req.query.email

  db.all(
    "SELECT * FROM Users WHERE email = '" + email + "'",
    (err, rows) => {
      res.json(rows)
    }
  )
})

// Command Injection
router.get('/unsafe-command', (req, res) => {
  const host = req.query.host

  exec('ping -c 1 ' + host, (err, stdout) => {
    res.send(stdout)
  })
})

// Path Traversal
router.get('/unsafe-file', (req, res) => {
  const file = req.query.file

  fs.readFile('./ftp/' + file, 'utf8', (err, data) => {
    res.send(data)
  })
})

// Arbitrary File Write
router.post('/unsafe-write', (req, res) => {
  const filename = req.query.filename

  fs.writeFileSync('./uploads/' + filename, req.body.content)

  res.send('ok')
})

// SSRF
router.get('/unsafe-fetch', async (req, res) => {
  const url = req.query.url

  const response = await axios.get(url)

  res.send(response.data)
})

// XSS
router.get('/unsafe-xss', (req, res) => {
  const name = req.query.name

  res.send('<h1>Hello ' + name + '</h1>')
})

// Code Injection
router.get('/unsafe-eval', (req, res) => {
  const expression = req.query.expression

  const result = eval(expression)

  res.send(String(result))
})

// Open Redirect
router.get('/unsafe-redirect', (req, res) => {
  res.redirect(req.query.url)
})

// Prototype Pollution
router.post('/unsafe-config', (req, res) => {
  const obj = {}

  obj[req.body.key] = req.body.value

  res.json(obj)
})

module.exports = router
