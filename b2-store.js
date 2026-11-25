const crypto = require("crypto");

const {
  S3Client,
  GetObjectCommand,
  PutObjectCommand
} = require("@aws-sdk/client-s3");

const BACKUP_KEY =
  "backups/shoplink-migration-1795580432255-504690a9-4592-4a30-aa6f-51eaff0bea19.json";

const EXPECTED_BACKUP_SHA256 =
  "b5c0dc9058258e92c1290e9bb7b600e5d26211cdcfbc230959b564fd3e478a9c";

const DATABASE_KEY =
  "data/shoplink-ghana-database.json";

function checksum(buffer) {
  return crypto
    .createHash("sha256")
    .update(buffer)
    .digest("hex");
}

function validateDatabase(database) {
  if (
    !database ||
    database.format !== "shoplink-ghana-database-v1" ||
    !Array.isArray(database.businesses) ||
    !Array.isArray(database.products)
  ) {
    throw new Error(
      "Invalid ShopLink database structure."
    );
  }

  const businessIds = new Set(
    database.businesses.map(
      item => String(item.id)
    )
  );

  if (
    database.businesses.some(
      item => !item.id || !item.slug || !item.password_hash
    )
  ) {
    throw new Error(
      "A business record is missing essential fields."
    );
  }

  if (
    database.products.some(
      item =>
        !item.id ||
        !businessIds.has(String(item.business_id))
    )
  ) {
    throw new Error(
      "A product has an invalid ID or business reference."
    );
  }

  return database;
}

async function getObjectBuffer(s3, bucket, key) {
  const result = await s3.send(
    new GetObjectCommand({
      Bucket: bucket,
      Key: key
    })
  );

  return Buffer.from(
    await result.Body.transformToByteArray()
  );
}

function isMissingObject(error) {
  return (
    error.name === "NoSuchKey" ||
    error.name === "NotFound" ||
    error.$metadata?.httpStatusCode === 404
  );
}

function clone(value) {
  return structuredClone(value);
}

function createB2Store() {
  const required = [
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
    throw new Error(
      `Missing B2 configuration: ${missing.join(", ")}`
    );
  }

  const bucket = process.env.B2_BUCKET_NAME;

  const s3 = new S3Client({
    region: process.env.B2_REGION,
    endpoint: process.env.B2_ENDPOINT,
    forcePathStyle: true,
    credentials: {
      accessKeyId: process.env.B2_KEY_ID,
      secretAccessKey: process.env.B2_APPLICATION_KEY
    }
  });

  let database = null;
  let writeQueue = Promise.resolve();

  async function initialize() {
    if (database) {
      return clone(database);
    }

    console.log("Checking ShopLink B2 database...");

    let existing;

    try {
      existing = await getObjectBuffer(
        s3,
        bucket,
        DATABASE_KEY
      );
    } catch (error) {
      if (!isMissingObject(error)) {
        throw error;
      }
    }

    if (existing) {
      const parsed = JSON.parse(
        existing.toString("utf8")
      );

      database = validateDatabase(parsed);

      console.log(
        "Existing ShopLink B2 database loaded."
      );

      return clone(database);
    }

    console.log(
      "Permanent database not found. Checking verified backup..."
    );

    const backup = await getObjectBuffer(
      s3,
      bucket,
      BACKUP_KEY
    );

    const actualChecksum = checksum(backup);

    if (actualChecksum !== EXPECTED_BACKUP_SHA256) {
      throw new Error(
        "Backup checksum mismatch. Database initialization stopped."
      );
    }

    const parsedBackup = validateDatabase(
      JSON.parse(backup.toString("utf8"))
    );

    const initialDatabase = {
      ...parsedBackup,
      updatedAt: new Date().toISOString()
    };

    const body = Buffer.from(
      JSON.stringify(initialDatabase),
      "utf8"
    );

    await s3.send(
      new PutObjectCommand({
        Bucket: bucket,
        Key: DATABASE_KEY,
        Body: body,
        ContentType: "application/json"
      })
    );

    const verification = await getObjectBuffer(
      s3,
      bucket,
      DATABASE_KEY
    );

    if (
      checksum(body) !== checksum(verification)
    ) {
      throw new Error(
        "Permanent database verification failed."
      );
    }

    database = validateDatabase(
      JSON.parse(verification.toString("utf8"))
    );

    console.log(
      "ShopLink B2 database initialized and verified."
    );

    console.log(
      `Businesses: ${database.businesses.length}`
    );

    console.log(
      `Products: ${database.products.length}`
    );

    return clone(database);
  }

  function read() {
    if (!database) {
      throw new Error(
        "B2 database has not been initialized."
      );
    }

    return clone(database);
  }

  function update(mutator) {
    const operation = writeQueue.then(async () => {
      if (!database) {
        throw new Error(
          "B2 database has not been initialized."
        );
      }

      const draft = clone(database);

      const result = await mutator(draft);

      validateDatabase(draft);

      draft.updatedAt = new Date().toISOString();

      const body = Buffer.from(
        JSON.stringify(draft),
        "utf8"
      );

      await s3.send(
        new PutObjectCommand({
          Bucket: bucket,
          Key: DATABASE_KEY,
          Body: body,
          ContentType: "application/json"
        })
      );

      database = draft;

      return result === undefined ? undefined : clone(result);
    });

    writeQueue = operation.catch(error => {
      console.error(
        "ShopLink B2 database write failed:",
        error
      );
    });

    return operation;
  }

  return {
    initialize,
    read,
    update
  };
}

module.exports = createB2Store;
