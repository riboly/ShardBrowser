// Download + verify Xray-core for the Tauri sidecar (Module 2 of the Xray fork).
//
// Usage:
//   node tools/download-xray.mjs [--target <rust-target>]
//   node tools/download-xray.mjs --check   # verify an already-downloaded binary, no network
//
// Behaviour (mirrors Donut's download-xray.mjs, pinned to the same version):
// - Xray version is pinned to v26.11.9 (2026-11-09; was v26.3.27 until
//   2026-11-10, when the old REALITY handshake got servers blocked).
//   Do NOT bump it as part of an upstream sync; an Xray upgrade is a
//   separate, explicitly approved task.
// - The release ZIP is verified by SHA256 in memory BEFORE it is written to
//   disk. A checksum mismatch fails the build; there is no fallback.
// - Only `xray` (+ `.exe` on Windows) and LICENSE are extracted, into
//   `src-tauri/binaries/xray-<target>[.exe]`, plus a `.source.json` marker.
//   The binary itself is never committed to git (see src-tauri/binaries/.gitignore).
// - If the binary, LICENSE and marker already match the pinned version and
//   checksums, the download is skipped (idempotent, CI-friendly).

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const XRAY_VERSION = "v26.11.9";
export const XRAY_SOURCE_URL = `https://github.com/XTLS/Xray-core/tree/${XRAY_VERSION}`;

export const XRAY_ASSETS = {
  "aarch64-apple-darwin": {
    name: "Xray-macos-arm64-v8a.zip",
    sha256: "233f0c66681cd0726f81a6b2b6ed6a5710869e312047b522e46ed53035bebd26",
  },
  "x86_64-apple-darwin": {
    name: "Xray-macos-64.zip",
    sha256: "488963e676e06f5e48547f9dd38116aaca8de4234959b4272ae8f284e658dfd0",
  },
  "x86_64-unknown-linux-gnu": {
    name: "Xray-linux-64.zip",
    sha256: "b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82",
  },
  "aarch64-unknown-linux-gnu": {
    name: "Xray-linux-arm64-v8a.zip",
    sha256: "64ed6858982a7f5eb85d88b811089063bd4f17561f4c8f44e0f1dc8e6f6430be",
  },
  "x86_64-pc-windows-msvc": {
    name: "Xray-windows-64.zip",
    sha256: "1262522266337b824f07beb8e1375786b437683b3890105469088f8e17e0a69d",
  },
};

const MANIFEST_DIR = dirname(fileURLToPath(import.meta.url));

export function requestedTarget() {
  const idx = process.argv.indexOf("--target");
  if (idx !== -1 && process.argv[idx + 1]) return process.argv[idx + 1];
  if (process.env.TARGET) return process.env.TARGET;
  const result = spawnSync("rustc", ["-vV"], { encoding: "utf8" });
  const match = result.stdout?.match(/^host:\s*(.+)$/m);
  if (!match) throw new Error("Unable to determine the Rust target");
  return match[1].trim();
}

function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

export function xrayBinaryName(target) {
  return `xray-${target}${target.includes("windows") ? ".exe" : ""}`;
}

export function xrayDownloadUrl(assetName) {
  return `https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/${assetName}`;
}

async function downloadVerifiedArchive(url, expectedSha256) {
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const response = await fetch(url);
      if (!response.ok) throw new Error(`Failed to download Xray-core (${response.status})`);
      const payload = Buffer.from(await response.arrayBuffer());
      const actual = sha256Hex(payload);
      if (actual !== expectedSha256) {
        throw new Error(`Xray-core checksum mismatch: expected ${expectedSha256}, got ${actual}`);
      }
      return payload;
    } catch (e) {
      if (attempt === 3) throw e;
      await new Promise((r) => setTimeout(r, attempt * 2000));
    }
  }
}

export async function downloadXray(target = requestedTarget()) {
  if (!Object.hasOwn(XRAY_ASSETS, target)) {
    throw new Error(`Xray-core is not packaged for Rust target '${target}'`);
  }
  const asset = XRAY_ASSETS[target];
  const windowsTarget = target.includes("windows");
  const destinationDir = join(MANIFEST_DIR, "..", "binaries");
  const destination = join(destinationDir, xrayBinaryName(target));
  const licenseDestination = join(destinationDir, "xray-LICENSE.txt");
  const marker = `${destination}.source.json`;

  if (existsSync(destination) && existsSync(licenseDestination) && existsSync(marker)) {
    try {
      const source = JSON.parse(readFileSync(marker, "utf8"));
      if (
        source.version === XRAY_VERSION &&
        source.archiveSha256 === asset.sha256 &&
        source.binarySha256 === sha256Hex(readFileSync(destination))
      ) {
        console.log(`Xray-core ${XRAY_VERSION} already present for ${target}, skipping download`);
        return destination;
      }
    } catch {
      // Partial or older cache entry: fall through and re-download.
    }
  }

  mkdirSync(destinationDir, { recursive: true });
  const scratch = mkdtempSync(join(tmpdir(), "shard-xray-"));
  try {
    const payload = await downloadVerifiedArchive(xrayDownloadUrl(asset.name), asset.sha256);
    const archive = join(scratch, basename(asset.name));
    writeFileSync(archive, payload);
    // Extract only xray + LICENSE. Windows uses PowerShell Expand-Archive
    // with env-var paths (see Donut's script for why $args is avoided).
    let binaryPath;
    if (windowsTarget) {
      const result = spawnSync(
        "powershell",
        [
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          "Expand-Archive -LiteralPath $env:SHARD_XRAY_ARCHIVE -DestinationPath $env:SHARD_XRAY_DESTINATION -Force",
        ],
        {
          stdio: "inherit",
          env: { ...process.env, SHARD_XRAY_ARCHIVE: archive, SHARD_XRAY_DESTINATION: scratch },
        },
      );
      if (result.status !== 0) throw new Error("Failed to extract the Xray-core archive");
      binaryPath = join(scratch, "xray.exe");
    } else {
      const result = spawnSync("unzip", ["-qq", "-j", archive, "xray", "LICENSE", "-d", scratch], {
        stdio: "inherit",
      });
      if (result.status !== 0) throw new Error("Failed to extract the Xray-core archive");
      binaryPath = join(scratch, "xray");
    }
    const licensePath = join(scratch, "LICENSE");
    if (!existsSync(binaryPath) || !existsSync(licensePath)) {
      throw new Error("The Xray-core archive did not contain its executable and license");
    }
    copyFileSync(binaryPath, destination);
    copyFileSync(licensePath, licenseDestination);
    if (!windowsTarget) chmodSync(destination, 0o755);
    writeFileSync(
      marker,
      JSON.stringify(
        {
          version: XRAY_VERSION,
          archiveSha256: asset.sha256,
          binarySha256: sha256Hex(readFileSync(destination)),
          licenseSha256: sha256Hex(readFileSync(licenseDestination)),
        },
        null,
        2,
      ) + "\n",
    );
    console.log(`Downloaded Xray-core ${XRAY_VERSION} to ${destination}`);
    return destination;
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv.includes("--check")) {
    const target = requestedTarget();
    const destination = join(MANIFEST_DIR, "..", "binaries", xrayBinaryName(target));
    if (!existsSync(destination)) {
      console.error(`Xray binary not found: ${destination}. Run without --check to download it.`);
      process.exit(1);
    }
    console.log(`Xray binary present: ${destination}`);
  } else {
    await downloadXray();
  }
}
