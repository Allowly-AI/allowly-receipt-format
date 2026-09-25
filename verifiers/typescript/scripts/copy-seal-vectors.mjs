import { copyFile, mkdir } from "node:fs/promises";

for (const [profile, names] of [
  ["seal", ["profile-v1.json", "verification-v1.json"]],
  ["policy", ["profile-v1.json"]],
]) {
  const source = new URL(`../../../vectors/${profile}/`, import.meta.url);
  const destination = new URL(`../dist/vectors/${profile}/`, import.meta.url);
  await mkdir(destination, { recursive: true });
  for (const name of names) {
    await copyFile(new URL(name, source), new URL(name, destination));
  }
}
