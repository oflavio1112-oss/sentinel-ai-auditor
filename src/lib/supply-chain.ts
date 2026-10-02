import type { Finding, ScannedPackage } from "./types";

const POPULAR_NPM = [
  "react",
  "react-dom",
  "lodash",
  "express",
  "axios",
  "vue",
  "next",
  "webpack",
  "typescript",
  "jquery",
  "moment",
  "request",
  "chalk",
  "debug",
  "glob",
  "minimist",
  "commander",
  "cors",
  "mongoose",
  "sequelize",
  "electron",
  "eslint",
  "prettier",
  "vite",
  "jest",
  "mocha",
  "node-fetch",
  "ws",
  "socket.io",
  "jsonwebtoken",
  "bcrypt",
  "dotenv",
  "nodemon",
  "cross-env",
  "body-parser",
  "uuid",
  "rxjs",
  "redux",
  "zustand",
  "tailwindcss",
  "prisma",
  "graphql",
  "passport",
  "multer",
  "helmet",
  "morgan",
  "cheerio",
  "puppeteer",
  "playwright",
  "three",
  "d3",
  "underscore",
  "async",
  "bluebird",
  "classnames",
  "prop-types",
  "styled-components",
  "sass",
  "less",
  "postcss",
  "babel-core",
  "core-js",
  "tslib",
  "zone.js",
  "angular",
  "svelte",
  "nuxt",
  "gatsby",
  "fastify",
  "koa",
  "hapi",
  "pm2",
  "winston",
  "dayjs",
  "date-fns",
  "ramda",
  "immutable",
  "mobx",
  "formik",
  "yup",
  "zod",
  "joi",
  "ajv",
  "webpack-cli",
  "nodemailer",
  "sharp",
  "aws-sdk",
  "firebase",
  "supabase",
];

export function supplyFindings(packages: ScannedPackage[]): Finding[] {
  const findings: Finding[] = [];
  const names = new Set(packages.map((p) => p.name.toLowerCase()));
  for (const pkg of packages) {
    if (pkg.ecosystem !== "npm") continue;
    const name = pkg.name.toLowerCase();
    if (POPULAR_NPM.includes(name)) continue;
    const hit = POPULAR_NPM.find((popular) => {
      if (names.has(popular)) return false;
      const d = levenshtein(name, popular);
      return d === 1 || (d === 2 && popular.length >= 8);
    });
    if (!hit) continue;
    findings.push({
      id: `typo:${pkg.name}`,
      kind: "hygiene",
      severity: "high",
      title: `Possível typosquat: ${pkg.name}`,
      description: `${pkg.name} fica a uma edição de "${hit}", pacote popular. Confira se não é confusão de dependência.`,
      packageName: pkg.name,
      packageVersion: pkg.version ?? undefined,
      ecosystem: pkg.ecosystem,
      remediation: `Confirme o pacote no npm. Se for erro, troque por ${hit}.`,
    });
  }

  const installScripts = packages.filter(
    (p) => p.ecosystem === "npm" && /postinstall|preinstall/i.test(p.name),
  );
  void installScripts;
  return findings;
}

function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  const row = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let prev = i - 1;
    row[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = row[j]!;
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      row[j] = Math.min(row[j]! + 1, row[j - 1]! + 1, prev + cost);
      prev = tmp;
    }
  }
  return row[b.length]!;
}
