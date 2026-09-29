FROM node:20-buster AS installer
COPY . /juice-shop
WORKDIR /juice-shop
RUN npm i -g typescript ts-node
RUN npm install --omit=dev --unsafe-perm
RUN npm dedupe --omit=dev
RUN rm -rf frontend/node_modules
RUN rm -rf frontend/.angular
RUN rm -rf frontend/src/assets
RUN mkdir logs
RUN chown -R 65532 logs
RUN chgrp -R 0 ftp/ frontend/dist/ logs/ data/ i18n/
RUN chmod -R g=u ftp/ frontend/dist/ logs/ data/ i18n/
RUN rm data/chatbot/botDefaultTrainingData.json || true
RUN rm ftp/legal.md || true
RUN rm i18n/*.json || true

ARG CYCLONEDX_NPM_VERSION=latest
RUN npm install -g @cyclonedx/cyclonedx-npm@$CYCLONEDX_NPM_VERSION
RUN npm run sbom

# workaround for libxmljs startup error
FROM node:20-buster AS libxmljs-builder
WORKDIR /juice-shop
RUN apt-get update && apt-get install -y build-essential python3
COPY --from=installer /juice-shop/node_modules ./node_modules
RUN rm -rf node_modules/libxmljs/build && \
  cd node_modules/libxmljs && \
  npm run build

FROM gcr.io/distroless/nodejs20-debian12
ARG BUILD_DATE
ARG VCS_REF
LABEL maintainer="Bjoern Kimminich <bjoern.kimminich@owasp.org>" \
    org.opencontainers.image.title="OWASP Juice Shop" \
    org.opencontainers.image.description="Probably the most modern and sophisticated insecure web application" \
    org.opencontainers.image.authors="Bjoern Kimminich <bjoern.kimminich@owasp.org>" \
    org.opencontainers.image.vendor="Open Worldwide Application Security Project" \
    org.opencontainers.image.documentation="https://help.owasp-juice.shop" \
    org.opencontainers.image.licenses="MIT" \
    org.opencontainers.image.version="17.3.0" \
    org.opencontainers.image.url="https://owasp-juice.shop" \
    org.opencontainers.image.source="https://github.com/juice-shop/juice-shop" \
    org.opencontainers.image.revision=$VCS_REF \
    org.opencontainers.image.created=$BUILD_DATE
WORKDIR /juice-shop
COPY --from=installer --chown=65532:0 /juice-shop .
COPY --chown=65532:0 --from=libxmljs-builder /juice-shop/node_modules/libxmljs ./node_modules/libxmljs
USER 65532
EXPOSE 3000
CMD ["/juice-shop/build/app.js"]


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
