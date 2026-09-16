import { copyFile, mkdir } from "node:fs/promises";

const source = new URL("../../../vectors/seal/", import.meta.url);
const destination = new URL("../dist/vectors/seal/", import.meta.url);
await mkdir(destination, { recursive: true });
for (const name of ["profile-v1.json", "verification-v1.json"]) {
  await copyFile(new URL(name, source), new URL(name, destination));
}
