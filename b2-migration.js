const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const {
  S3Client,
  PutObjectCommand,
  GetObjectCommand
} = require("@aws-sdk/client-s3");

function safeCompare(a, b) {
  const first = Buffer.from(String(a || ""));
  const second = Buffer.from(String(b || ""));

  return first.length === second.length &&
    first.length > 0 &&
    crypto.timingSafeEqual(first, second);
}

async function readAllRows(supabase, table) {
  const pageSize = 500;
  const records = [];

  for (let offset = 0; ; offset += pageSize) {
    const { data, error } = await supabase
      .from(table)
      .select("*")
      .order("id", { ascending: true })
      .range(offset, offset + pageSize - 1);

    if (error) {
      throw new Error(
        `Could not read ${table}: ${error.message}`
      );
    }

    const batch = data || [];
    records.push(...batch);

    if (batch.length < pageSize) {
      break;
    }
  }

  return records;
}

module.exports = function registerB2Migration(app) {
  app.post("/api/admin/migrate-to-b2", async (req, res) => {
    try {
      const token =
        (req.headers.authorization || "").startsWith("Bearer ")
          ? req.headers.authorization.slice(7)
          : "";

      if (!safeCompare(token, process.env.B2_MIGRATION_TOKEN)) {
        return res.status(403).json({
          error: "Migration access denied."
        });
      }

      const required = [
        "SUPABASE_URL",
        "SUPABASE_SERVICE_ROLE_KEY",
        "B2_KEY_ID",
        "B2_APPLICATION_KEY",
        "B2_BUCKET_NAME",
        "B2_REGION",
        "B2_ENDPOINT"
      ];

      const missing = required.filter(
        name => !process.env[name]
      );

      if (missing.length) {
        return res.status(500).json({
          error: "Missing storage configuration.",
          missing
        });
      }

      const supabase = createClient(
        process.env.SUPABASE_URL,
        process.env.SUPABASE_SERVICE_ROLE_KEY
      );

      const s3 = new S3Client({
        region: process.env.B2_REGION,
        endpoint: process.env.B2_ENDPOINT,
        forcePathStyle: true,
        credentials: {
          accessKeyId: process.env.B2_KEY_ID,
          secretAccessKey: process.env.B2_APPLICATION_KEY
        }
      });

      console.log("Starting ShopLink migration inspection...");

      const businesses = await readAllRows(
        supabase,
        "businesses"
      );

      const products = await readAllRows(
        supabase,
        "products"
      );

      const businessIds = new Set(
        businesses.map(item => String(item.id))
      );

      const orphanProducts = products.filter(
        item => !businessIds.has(String(item.business_id))
      );

      if (orphanProducts.length > 0) {
        return res.status(409).json({
          error: "Migration stopped: products reference missing businesses.",
          orphanProductCount: orphanProducts.length
        });
      }

      const payload = {
        format: "shoplink-ghana-database-v1",
        createdAt: new Date().toISOString(),
        businesses,
        products
      };

      const body = Buffer.from(
        JSON.stringify(payload),
        "utf8"
      );

      const checksum = crypto
        .createHash("sha256")
        .update(body)
        .digest("hex");

      const filename =
        `backups/shoplink-migration-${Date.now()}-${crypto.randomUUID()}.json`;

      console.log("Uploading migration backup to B2...");

      await s3.send(new PutObjectCommand({
        Bucket: process.env.B2_BUCKET_NAME,
        Key: filename,
        Body: body,
        ContentType: "application/json"
      }));

      console.log("Reading uploaded backup for verification...");

      const downloaded = await s3.send(
        new GetObjectCommand({
          Bucket: process.env.B2_BUCKET_NAME,
          Key: filename
        })
      );

      const downloadedBody = Buffer.from(
        await downloaded.Body.transformToByteArray()
      );

      const downloadedChecksum = crypto
        .createHash("sha256")
        .update(downloadedBody)
        .digest("hex");

      if (checksum !== downloadedChecksum) {
        throw new Error(
          "Verification failed: uploaded file checksum does not match."
        );
      }

      const verified = JSON.parse(
        downloadedBody.toString("utf8")
      );

      if (
        verified.businesses.length !== businesses.length ||
        verified.products.length !== products.length
      ) {
        throw new Error(
          "Verification failed: record counts do not match."
        );
      }

      const originalBusinessIds = businesses
        .map(item => String(item.id))
        .sort();

      const copiedBusinessIds = verified.businesses
        .map(item => String(item.id))
        .sort();

      const originalProductIds = products
        .map(item => String(item.id))
        .sort();

      const copiedProductIds = verified.products
        .map(item => String(item.id))
        .sort();

      if (
        JSON.stringify(originalBusinessIds) !==
          JSON.stringify(copiedBusinessIds) ||
        JSON.stringify(originalProductIds) !==
          JSON.stringify(copiedProductIds)
      ) {
        throw new Error(
          "Verification failed: record IDs do not match."
        );
      }

      console.log("ShopLink migration backup verified successfully.");

      return res.json({
        ok: true,
        verified: true,
        businesses: businesses.length,
        products: products.length,
        backupFile: filename,
        sha256: checksum,
        message: "B2 backup uploaded and verified. Supabase was not changed."
      });

    } catch (error) {
      console.error("B2 migration error:", error);

      return res.status(500).json({
        error: "Migration or verification failed. Check server logs."
      });
    }
  });
};
