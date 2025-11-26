import winston from "winston";
import DailyRotateFile from "winston-daily-rotate-file";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import * as fs from "fs";
import * as path from "path";
import * as zlib from "zlib";

// -------------------------------
//  S3 CLIENT
// -------------------------------
const s3 = new S3Client({
  region: process.env.AWS_REGION || "us-east-1",
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID!,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!,
  },
});

// -------------------------------
//  LOG DIRECTORY SETUP
// -------------------------------
const LOG_DIR = "logs";
if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR);

// -------------------------------
//  LOG FORMAT
// -------------------------------
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: "YYYY-MM-DD HH:mm:ss" }),
  winston.format.errors({ stack: true }),
  winston.format.splat(),
  winston.format.json()
);

// -------------------------------
//  FUNCTION: COMPRESS A FILE (.log -> .gz)
// -------------------------------
async function gzipFile(filePath: string): Promise<string> {
  const gzPath = filePath + ".gz";
  return new Promise((resolve, reject) => {
    const input = fs.createReadStream(filePath);
    const output = fs.createWriteStream(gzPath);
    const gzip = zlib.createGzip();

    input.pipe(gzip).pipe(output);

    output.on("finish", () => resolve(gzPath));
    output.on("error", reject);
  });
}

// -------------------------------
//  FUNCTION: UPLOAD TO S3
// -------------------------------
async function uploadToS3(filePath: string) {
  try {
    const fileContent = fs.readFileSync(filePath);
    const fileName = path.basename(filePath);

    const key = `logs/${new Date().getFullYear()}/${fileName}`;

    await s3.send(
      new PutObjectCommand({
        Bucket: process.env.S3_BUCKET_NAME!,
        Key: key,
        Body: fileContent,
        ContentType: "application/gzip",
      })
    );

    console.log("Uploaded to S3:", key);

    // optional: delete after upload
    // fs.unlinkSync(filePath);

  } catch (err) {
    console.error("S3 upload failed:", err);
  }
}

// -------------------------------
//  ROTATION HANDLER (RELIABLE)
// -------------------------------
async function handleRotation(oldFilename: string) {
  try {
    // 1. Gzip the rotated .log file
    const gzFile = await gzipFile(oldFilename);

    // 2. Upload the .gz file to S3
    await uploadToS3(gzFile);

    // 3. Optional: cleanup
    // fs.unlinkSync(oldFilename);
    // fs.unlinkSync(gzFile);

  } catch (e) {
    console.error("Rotation handling failed:", e);
  }
}

// -------------------------------
//  WINSTON TRANSPORT (ROTATES EVERY MINUTE)
// -------------------------------
const rotateTransport = new DailyRotateFile({
  filename: path.join(LOG_DIR, "app-%DATE%.log"),
  datePattern: "YYYY-MM-DD", // per-minute rotation
  zippedArchive: false,            // we gzip manually
  maxSize: "20m",
  maxFiles: "14d",
  format: logFormat,
});

// When rotation happens → handle it cleanly
rotateTransport.on("rotate", (oldFile) => {
  handleRotation(oldFile);
});

// -------------------------------
//  LOGGER EXPORT
// -------------------------------
const logger = winston.createLogger({
  level: "info",
  format: logFormat,
  transports: [
    rotateTransport,
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
    }),
  ],
});

export default logger;
