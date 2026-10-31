#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Someone-anon-coder
# Copy only the files the app serves into _site/ (used by Cloudflare and GitHub Pages).
set -e
cd "$(dirname "$0")/.."
rm -rf _site
mkdir _site
cp index.html app.css app.js core.js worker.js sw.js manifest.webmanifest _headers _site/
cp -r icons vendor _site/
