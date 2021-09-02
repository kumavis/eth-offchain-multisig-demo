import * as wasm from "emerald-city";

const signThreshold = 2;
const numParties = 3;
const keys = wasm.keygen(signThreshold, numParties);
console.log("JS: generated keys", keys);

