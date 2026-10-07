// Prints the SHA-256 of every file a build serves or runs (dist/server.mjs and dist/public/**),
// sorted by path, and one hash over that list: compare it with the hashes published with a
// release (README, "Reproducible builds") to check that what you run is what the source builds.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const root = path.resolve(process.argv[2] ?? "dist");
const files = [];
const walk = (dir) => {
  for (const name of fs.readdirSync(dir).sort()) {
    const full = path.join(dir, name);
    const st = fs.statSync(full);
    if (st.isDirectory()) walk(full);
    else if (name !== "HASHES.txt") files.push(full);
  }
};
walk(root);
const lines = files.map((f) => `${crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex")}  ${path.relative(root, f).split(path.sep).join("/")}`);
lines.sort((a, b) => a.slice(66).localeCompare(b.slice(66)));
const tree = crypto.createHash("sha256").update(lines.join("\n") + "\n").digest("hex");
process.stdout.write(`${lines.join("\n")}\n\nbuild ${tree}\n`);
