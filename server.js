const express = require("express");
const crypto = require("crypto");
const path = require("path");
const { createClient } = require("@supabase/supabase-js");

const app = express();

const PORT = process.env.PORT || 10000;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY;

const AUTH_SECRET = process.env.AUTH_SECRET;
const ADMIN_PASSWORD =
  process.env.SHOPLINK_ADMIN_PASSWORD;

/* =========================================================
   CHECK ENVIRONMENT VARIABLES
========================================================= */

if (
  !SUPABASE_URL ||
  !SUPABASE_SERVICE_ROLE_KEY ||
  !AUTH_SECRET ||
  !ADMIN_PASSWORD
) {
  console.error(
    "Missing required environment variables."
  );

  console.error(
    "Required:"
  );

  console.error(
    "SUPABASE_URL"
  );

  console.error(
    "SUPABASE_SERVICE_ROLE_KEY"
  );

  console.error(
    "AUTH_SECRET"
  );

  console.error(
    "SHOPLINK_ADMIN_PASSWORD"
  );

  process.exit(1);
}

/* =========================================================
   SUPABASE
========================================================= */

const supabase = createClient(
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY
);

/* =========================================================
   EXPRESS
========================================================= */

app.use(express.json());

app.use(
  express.static(
    path.join(__dirname, "public")
  )
);

/* =========================================================
   HELPERS
========================================================= */

function slugify(text) {
  return String(text)
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 60);
}

/* =========================================================
   PASSWORD HASHING
========================================================= */

function hashPassword(password) {
  const salt =
    crypto.randomBytes(16).toString("hex");

  const hash =
    crypto.scryptSync(
      String(password),
      salt,
      64
    ).toString("hex");

  return `${salt}:${hash}`;
}

function verifyPassword(
  password,
  storedHash
) {
  try {
    if (!storedHash) {
      return false;
    }

    const parts =
      String(storedHash).split(":");

    if (parts.length !== 2) {
      return false;
    }

    const salt = parts[0];

    const originalHash =
      Buffer.from(
        parts[1],
        "hex"
      );

    const testHash =
      crypto.scryptSync(
        String(password),
        salt,
        64
      );

    if (
      originalHash.length !==
      testHash.length
    ) {
      return false;
    }

    return crypto.timingSafeEqual(
      originalHash,
      testHash
    );
  } catch (error) {
    console.error(
      "Password verification error:",
      error
    );

    return false;
  }
}

/* =========================================================
   ADMIN PASSWORD CHECK
========================================================= */

function checkAdminPassword(password) {
  if (
    password === undefined ||
    password === null
  ) {
    return false;
  }

  const supplied =
    Buffer.from(
      String(password),
      "utf8"
    );

  const actual =
    Buffer.from(
      String(ADMIN_PASSWORD),
      "utf8"
    );

  if (
    supplied.length !==
    actual.length
  ) {
    return false;
  }

  return crypto.timingSafeEqual(
    supplied,
    actual
  );
}

/* =========================================================
   LOGIN TOKEN
========================================================= */

function createToken(businessId) {
  const expires =
    Date.now() +
    24 * 60 * 60 * 1000;

  const payload =
    `${businessId}.${expires}`;

  const signature =
    crypto
      .createHmac(
        "sha256",
        AUTH_SECRET
      )
      .update(payload)
      .digest("hex");

  return `${payload}.${signature}`;
}

function verifyToken(token) {
  try {
    if (!token) {
      return null;
    }

    const parts =
      String(token).split(".");

    if (parts.length !== 3) {
      return null;
    }

    const businessId =
      parts[0];

    const expires =
      Number(parts[1]);

    const signature =
      parts[2];

    if (
      !businessId ||
      !expires ||
      !signature
    ) {
      return null;
    }

    if (
      Date.now() > expires
    ) {
      return null;
    }

    const payload =
      `${businessId}.${expires}`;

    const expectedSignature =
      crypto
        .createHmac(
          "sha256",
          AUTH_SECRET
        )
        .update(payload)
        .digest("hex");

    const suppliedBuffer =
      Buffer.from(
        signature,
        "utf8"
      );

    const expectedBuffer =
      Buffer.from(
        expectedSignature,
        "utf8"
      );

    if (
      suppliedBuffer.length !==
      expectedBuffer.length
    ) {
      return null;
    }

    if (
      !crypto.timingSafeEqual(
        suppliedBuffer,
        expectedBuffer
      )
    ) {
      return null;
    }

    return businessId;
  } catch (error) {
    console.error(
      "Token verification error:",
      error
    );

    return null;
  }
}

/* =========================================================
   GET TOKEN
========================================================= */

function getTokenFromRequest(req) {
  const header =
    req.headers.authorization || "";

  if (
    !header.startsWith(
      "Bearer "
    )
  ) {
    return null;
  }

  return header.slice(7);
}

/* =========================================================
   AUTH MIDDLEWARE
========================================================= */

async function requireAuth(
  req,
  res,
  next
) {
  try {
    const token =
      getTokenFromRequest(req);

    if (!token) {
      return res.status(401).json({
        error:
          "You must be logged in."
      });
    }

    const businessId =
      verifyToken(token);

    if (!businessId) {
      return res.status(401).json({
        error:
          "Your session has expired. Please log in again."
      });
    }

    const {
      data: business,
      error
    } =
      await supabase
        .from("businesses")
        .select("*")
        .eq(
          "id",
          businessId
        )
        .maybeSingle();

    if (error) {
      console.error(error);

      return res.status(500).json({
        error:
          "Could not verify your shop."
      });
    }

    if (!business) {
      return res.status(401).json({
        error:
          "Shop not found."
      });
    }

    req.businessId =
      business.id;

    req.business =
      business;

    next();
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      error:
        "Authentication error."
    });
  }
}

/* =========================================================
   PUBLIC SHOP
========================================================= */

app.get(
  "/api/business/:slug",
  async (req, res) => {
    try {
      const slug =
        String(
          req.params.slug
        )
          .toLowerCase()
          .trim();

      const {
        data: business,
        error: businessError
      } =
        await supabase
          .from("businesses")
          .select(
            "id,name,slug,whatsapp,location,hours,description,created_at"
          )
          .eq(
            "slug",
            slug
          )
          .maybeSingle();

      if (businessError) {
        console.error(
          businessError
        );

        return res.status(500).json({
          error:
            "Could not load shop."
        });
      }

      if (!business) {
        return res.status(404).json({
          error:
            "Shop not found."
        });
      }

      const {
        data: products,
        error: productsError
      } =
        await supabase
          .from("products")
          .select(
            "id,name,price,image,description,created_at"
          )
          .eq(
            "business_id",
            business.id
          )
          .order(
            "created_at",
            {
              ascending: false
            }
          );

      if (productsError) {
        console.error(
          productsError
        );

        return res.status(500).json({
          error:
            "Could not load products."
        });
      }

      return res.json({
        business,
        products:
          products || []
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        error:
          "Server error."
      });
    }
  }
);

/* =========================================================
   ADMIN CREATE SHOP
========================================================= */

app.post(
  "/api/admin/businesses",
  async (req, res) => {
    try {
      const {
        adminPassword,
        name,
        whatsapp,
        location,
        hours,
        description,
        password
      } = req.body;

      /* -----------------------------------------------
         ADMIN PASSWORD
      ------------------------------------------------ */

      if (
        !checkAdminPassword(
          adminPassword
        )
      ) {
        return res.status(403).json({
          error:
            "Incorrect admin password."
        });
      }

      /* -----------------------------------------------
         REQUIRED FIELDS
      ------------------------------------------------ */

      if (
        !name ||
        !whatsapp ||
        !password
      ) {
        return res.status(400).json({
          error:
            "Shop name, WhatsApp number and seller password are required."
        });
      }

      if (
        String(password).length < 6
      ) {
        return res.status(400).json({
          error:
            "Seller password must be at least 6 characters."
        });
      }

      /* -----------------------------------------------
         CREATE SLUG
      ------------------------------------------------ */

      const slug =
        slugify(name);

      if (!slug) {
        return res.status(400).json({
          error:
            "Please enter a valid shop name."
        });
      }

      /* -----------------------------------------------
         CHECK EXISTING SHOP
      ------------------------------------------------ */

      const {
        data: existing,
        error: existingError
      } =
        await supabase
          .from("businesses")
          .select(
            "id,slug"
          )
          .eq(
            "slug",
            slug
          )
          .maybeSingle();

      if (existingError) {
        console.error(
          existingError
        );

        return res.status(500).json({
          error:
            "Could not check existing shops."
        });
      }

      if (existing) {
        return res.status(409).json({
          error:
            "A shop with this name already exists. Please use a different name."
        });
      }

      /* -----------------------------------------------
         HASH SELLER PASSWORD
      ------------------------------------------------ */

      const passwordHash =
        hashPassword(
          password
        );

      /* -----------------------------------------------
         CREATE SHOP
      ------------------------------------------------ */

      const {
        data: business,
        error
      } =
        await supabase
          .from("businesses")
          .insert({
            name:
              String(name).trim(),

            slug,

            whatsapp:
              String(
                whatsapp
              ).trim(),

            location:
              String(
                location ||
                  "Ghana"
              ).trim(),

            hours:
              String(
                hours ||
                  "Contact seller"
              ).trim(),

            description:
              String(
                description ||
                  ""
              ).trim(),

            password_hash:
              passwordHash
          })
          .select(
            "id,name,slug,whatsapp,location,hours,description,created_at"
          )
          .single();

      if (error) {
        console.error(
          "Create shop error:",
          error
        );

        return res.status(500).json({
          error:
            "Could not create shop."
        });
      }

      return res.status(201).json({
        ok: true,

        business,

        shopUrl:
          `/shop/${business.slug}`
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        error:
          "Server error while creating shop."
      });
    }
  }
);

/* =========================================================
   SELLER LOGIN
========================================================= */

app.post(
  "/api/login",
  async (req, res) => {
    try {
      const {
        slug,
        password
      } = req.body;

      if (
        !slug ||
        !password
      ) {
        return res.status(400).json({
          error:
            "Shop name/slug and password are required."
        });
      }

      const cleanSlug =
        slugify(slug);

      const {
        data: business,
        error
      } =
        await supabase
          .from("businesses")
          .select("*")
          .eq(
            "slug",
            cleanSlug
          )
          .maybeSingle();

      if (error) {
        console.error(error);

        return res.status(500).json({
          error:
            "Could not log in."
        });
      }

      if (!business) {
        return res.status(401).json({
          error:
            "Shop not found or incorrect password."
        });
      }

      const sellerPasswordCorrect =
        verifyPassword(
          password,
          business.password_hash
        );

      if (
        !sellerPasswordCorrect
      ) {
        return res.status(401).json({
          error:
            "Incorrect password."
        });
      }

      const token =
        createToken(
          business.id
        );

      return res.json({
        ok: true,

        token,

        business: {
          id:
            business.id,

          name:
            business.name,

          slug:
            business.slug,

          whatsapp:
            business.whatsapp,

          location:
            business.location,

          hours:
            business.hours,

          description:
            business.description,

          created_at:
            business.created_at
        }
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        error:
          "Server error while logging in."
      });
    }
  }
);

/* =========================================================
   SELLER DASHBOARD
========================================================= */

app.get(
  "/api/me",
  requireAuth,
  async (req, res) => {
    try {
      const {
        data: products,
        error
      } =
        await supabase
          .from("products")
          .select("*")
          .eq(
            "business_id",
            req.businessId
          )
          .order(
            "created_at",
            {
              ascending: false
            }
          );

      if (error) {
        console.error(error);

        return res.status(500).json({
          error:
            "Could not load products."
        });
      }

      return res.json({
        business: {
          id:
            req.business.id,

          name:
            req.business.name,

          slug:
            req.business.slug,

          whatsapp:
            req.business.whatsapp,

          location:
            req.business.location,

          hours:
            req.business.hours,

          description:
            req.business.description,

          created_at:
            req.business.created_at
        },

        products:
          products || []
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        error:
          "Server error."
      });
    }
  }
);

/* =========================================================
   ADD PRODUCT
========================================================= */

app.post(
  "/api/products",
  requireAuth,
  async (req, res) => {
    try {
      const {
        name,
        price,
        image,
        description
      } = req.body;

      if (
        !name ||
        price === undefined ||
        price === ""
      ) {
        return res.status(400).json({
          error:
            "Product name and price are required."
        });
      }

      const numericPrice =
        Number(price);

      if (
        !Number.isFinite(
          numericPrice
        ) ||
        numericPrice < 0
      ) {
        return res.status(400).json({
          error:
            "Please enter a valid price."
        });
      }

      const {
        data: product,
        error
      } =
        await supabase
          .from("products")
          .insert({
            business_id:
              req.businessId,

            name:
              String(name).trim(),

            price:
              numericPrice,

            image:
              String(
                image || ""
              ).trim(),

            description:
              String(
                description || ""
              ).trim()
          })
          .select("*")
          .single();

      if (error) {
        console.error(error);

        return res.status(500).json({
          error:
            "Could not add product."
        });
      }

      return res.status(201).json({
        ok: true,
        product
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        error:
          "Server error while adding product."
      });
    }
  }
);

/* =========================================================
   EDIT PRODUCT
========================================================= */

app.put(
  "/api/products/:id",
  requireAuth,
  async (req, res) => {
    try {
      const productId =
        req.params.id;

      const {
        name,
        price,
        image,
        description
      } = req.body;

      if (
        !name ||
        price === undefined ||
        price === ""
      ) {
        return res.status(400).json({
          error:
            "Product name and price are required."
        });
      }

      const numericPrice =
        Number(price);

      if (
        !Number.isFinite(
          numericPrice
        ) ||
        numericPrice < 0
      ) {
        return res.status(400).json({
          error:
            "Please enter a valid price."
        });
      }

      const {
        data: product,
        error
      } =
        await supabase
          .from("products")
          .update({
            name:
              String(name).trim(),

            price:
              numericPrice,

            image:
              String(
                image || ""
              ).trim(),

            description:
              String(
                description || ""
              ).trim()
          })
          .eq(
            "id",
            productId
          )
          .eq(
            "business_id",
            req.businessId
          )
          .select("*")
          .maybeSingle();

      if (error) {
        console.error(error);

        return res.status(500).json({
          error:
            "Could not update product."
        });
      }

      if (!product) {
        return res.status(404).json({
          error:
            "Product not found."
        });
      }

      return res.json({
        ok: true,
        product
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        error:
          "Server error while updating product."
      });
    }
  }
);

/* =========================================================
   DELETE PRODUCT
========================================================= */

app.delete(
  "/api/products/:id",
  requireAuth,
  async (req, res) => {
    try {
      const productId =
        req.params.id;

      const {
        data: deletedProduct,
        error
      } =
        await supabase
          .from("products")
          .delete()
          .eq(
            "id",
            productId
          )
          .eq(
            "business_id",
            req.businessId
          )
          .select("id")
          .maybeSingle();

      if (error) {
        console.error(error);

        return res.status(500).json({
          error:
            "Could not delete product."
        });
      }

      if (!deletedProduct) {
        return res.status(404).json({
          error:
            "Product not found."
        });
      }

      return res.json({
        ok: true,

        message:
          "Product deleted successfully."
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        error:
          "Server error while deleting product."
      });
    }
  }
);

/* =========================================================
   DELETE SHOP
========================================================= */

app.delete(
  "/api/business/me",
  requireAuth,
  async (req, res) => {
    try {
      /*
        This assumes your Supabase database has
        ON DELETE CASCADE configured from products.business_id
        to businesses.id.

        If it does not, we delete products first.
      */

      const {
        error: productsError
      } =
        await supabase
          .from("products")
          .delete()
          .eq(
            "business_id",
            req.businessId
          );

      if (productsError) {
        console.error(
          "Delete products error:",
          productsError
        );

        return res.status(500).json({
          error:
            "Could not delete the shop products."
        });
      }

      const {
        error: businessError
      } =
        await supabase
          .from("businesses")
          .delete()
          .eq(
            "id",
            req.businessId
          );

      if (businessError) {
        console.error(
          "Delete shop error:",
          businessError
        );

        return res.status(500).json({
          error:
            "Could not delete shop."
        });
      }

      return res.json({
        ok: true,

        message:
          "Shop and all products deleted successfully."
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        error:
          "Server error while deleting shop."
      });
    }
  }
);

/* =========================================================
   ADMIN RESET SELLER PASSWORD
========================================================= */

app.post(
  "/api/admin/reset-password",
  async (req, res) => {
    try {
      const {
        adminPassword,
        slug,
        newPassword
      } = req.body;

      if (
        !checkAdminPassword(
          adminPassword
        )
      ) {
        return res.status(403).json({
          error:
            "Incorrect admin password."
        });
      }

      if (
        !slug ||
        !newPassword
      ) {
        return res.status(400).json({
          error:
            "Shop slug and new password are required."
        });
      }

      if (
        String(newPassword).length < 6
      ) {
        return res.status(400).json({
          error:
            "New password must be at least 6 characters."
        });
      }

      const cleanSlug =
        slugify(slug);

      const passwordHash =
        hashPassword(
          newPassword
        );

      const {
        data: business,
        error
      } =
        await supabase
          .from("businesses")
          .update({
            password_hash:
              passwordHash
          })
          .eq(
            "slug",
            cleanSlug
          )
          .select(
            "id,name,slug"
          )
          .maybeSingle();

      if (error) {
        console.error(error);

        return res.status(500).json({
          error:
            "Could not reset password."
        });
      }

      if (!business) {
        return res.status(404).json({
          error:
            "Shop not found."
        });
      }

      return res.json({
        ok: true,

        message:
          "Seller password reset successfully.",

        business
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        error:
          "Server error while resetting password."
      });
    }
  }
);

/* =========================================================
   PAGES
========================================================= */

/*
  Public shop page
*/

app.get(
  "/shop/:slug",
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        "public",
        "shop.html"
      )
    );
  }
);

/*
  Seller dashboard
*/

app.get(
  "/seller",
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        "public",
        "seller.html"
      )
    );
  }
);

/* =========================================================
   DEFAULT PAGE
========================================================= */

/*
  IMPORTANT:
  Do NOT use app.get("*") here.

  Newer Express versions reject "*".
  This middleware handles all remaining
  browser requests instead.
*/

app.use(
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        "public",
        "index.html"
      )
    );
  }
);

/* =========================================================
   START SERVER
========================================================= */

app.listen(
  PORT,
  () => {
    console.log(
      `ShopLink Ghana running on port ${PORT}`
    );
  }
);
