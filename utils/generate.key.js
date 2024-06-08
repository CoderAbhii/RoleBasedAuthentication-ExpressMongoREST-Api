import crypto from "crypto"


const keyOne = crypto.randomBytes(30).toString("hex");
const keyTwo = crypto.randomBytes(30).toString("hex");

console.table({keyOne, keyTwo});