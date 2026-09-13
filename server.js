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

if (
  !SUPABASE_URL ||
  !SUPABASE_SERVICE_ROLE_KEY ||
  !AUTH_SECRET ||
  !ADMIN_PASSWORD
) {
  console.error(
    "Missing required environment variables."
  );
  process.exit(1);
}

const supabase = createClient(
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY
);

app.use(express.json());

app.use(
  express.static(path.join(__dirname, "public"))
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

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");

  const hash = crypto
    .scryptSync(password, salt, 64)
    .toString("hex");

  return `${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {
  try {
    const parts = storedHash.split(":");

    if (parts.length !== 2) {
      return false;
    }

    const salt = parts[0];
    const originalHash = Buffer.from(parts[1], "hex");

    const testHash = crypto.scryptSync(
      password,
      salt,
      64
    );

    return crypto.timingSafeEqual(
      originalHash,
      testHash
    );
  } catch (error) {
    return false;
  }
}

function createToken(businessId) {
  const expires = Date.now() + 24 * 60 * 60 * 1000;

  const payload = `${businessId}.${expires}`;

  const signature = crypto
    .createHmac("sha256", AUTH_SECRET)
    .update(payload)
    .digest("hex");

  return `${payload}.${signature}`;
}

function verifyToken(token) {
  try {
    const parts = token.split(".");

    if (parts.length !== 3) {
      return null;
    }

    const businessId = parts[0];
    const expires = Number(parts[1]);
    const signature = parts[2];

    if (!businessId || !expires || !signature) {
      return null;
    }

    if (Date.now() > expires) {
      return null;
    }

    const payload = `${businessId}.${expires}`;

    const expectedSignature = crypto
      .createHmac("sha256", AUTH_SECRET)
      .update(payload)
      .digest("hex");

    const sigA = Buffer.from(signature, "utf8");
    const sigB = Buffer.from(
      expectedSignature,
      "utf8"
    );

    if (sigA.length !== sigB.length) {
      return null;
    }

    if (!crypto.timingSafeEqual(sigA, sigB)) {
      return null;
    }

    return businessId;
  } catch (error) {
    return null;
  }
}

function getTokenFromRequest(req) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  return header.slice(7);
}

async function requireAuth(req, res, next) {
  try {
    const token = getTokenFromRequest(req);

    if (!token) {
      return res.status(401).json({
        error: "You must be logged in."
      });
    }

    const businessId = verifyToken(token);

    if (!businessId) {
      return res.status(401).json({
        error: "Your session has expired. Please log in again."
      });
    }

    const { data: business, error } =
      await supabase
        .from("businesses")
        .select("*")
        .eq("id", businessId)
        .maybeSingle();

    if (error) {
      console.error(error);

      return res.status(500).json({
        error: "Could not verify your shop."
      });
    }

    if (!business) {
      return res.status(401).json({
        error: "Shop not found."
      });
    }

    req.businessId = business.id;
    req.business = business;

    next();
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      error: "Authentication error."
    });
  }
}

function checkAdminPassword(password) {
  if (!password) {
    return false;
  }

  return crypto.timingSafeEqual(
    Buffer.from(String(password)),
    Buffer.from(String(ADMIN_PASSWORD))
  );
}

/* =========================================================
   PUBLIC SHOP
========================================================= */

app.get("/api/business/:slug", async (req, res) => {
  try {
    const slug = String(req.params.slug)
      .toLowerCase()
      .trim();

    const { data: business, error: businessError } =
      await supabase
        .from("businesses")
        .select(
          "id,name,slug,whatsapp,location,hours,description,created_at"
        )
        .eq("slug", slug)
        .maybeSingle();

    if (businessError) {
      console.error(businessError);

      return res.status(500).json({
        error: "Could not load shop."
      });
    }

    if (!business) {
      return res.status(404).json({
        error: "Shop not found."
      });
    }

    const { data: products, error: productsError } =
      await supabase
        .from("products")
        .select(
          "id,name,price,image,description,created_at"
        )
        .eq("business_id", business.id)
        .order("created_at", {
          ascending: false
        });

    if (productsError) {
      console.error(productsError);

      return res.status(500).json({
        error: "Could not load products."
      });
    }

    return res.json({
      business,
      products: products || []
    });
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      error: "Server error."
    });
  }
});

/* =========================================================
   ADMIN - CREATE SHOP
   PUBLIC CREATE SHOP HAS BEEN REMOVED
========================================================= */

app.post("/api/admin/businesses", async (req, res) => {
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

    if (!checkAdminPassword(adminPassword)) {
      return res.status(403).json({
        error: "Incorrect admin password."
      });
    }

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

    if (String(password).length < 6) {
      return res.status(400).json({
        error:
          "Seller password must be at least 6 characters."
      });
    }

    let slug = slugify(name);

    if (!slug) {
      return res.status(400).json({
        error: "Please enter a valid shop name."
      });
    }

    const { data: existing } =
      await supabase
        .from("businesses")
        .select("id,slug")
        .eq("slug", slug)
        .maybeSingle();

    if (existing) {
      return res.status(409).json({
        error:
          "A shop with this name already exists. Please use a different name."
      });
    }

    const passwordHash =
      hashPassword(password);

    const { data: business, error } =
      await supabase
        .from("businesses")
        .insert({
          name: String(name).trim(),
          slug,
          whatsapp: String(whatsapp).trim(),
          location:
            String(location || "Ghana").trim(),
          hours:
            String(hours || "Contact seller").trim(),
          description:
            String(description || "").trim(),
          password_hash: passwordHash
        })
        .select(
          "id,name,slug,whatsapp,location,hours,description,created_at"
        )
        .single();

    if (error) {
      console.error("Create shop error:", error);

      return res.status(500).json({
        error: "Could not create shop."
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
      error: "Server error while creating shop."
    });
  }
});

/* =========================================================
   SELLER LOGIN
========================================================= */

app.post("/api/login", async (req, res) => {
  try {
    const {
      slug,
      password
    } = req.body;

    if (!slug || !password) {
      return res.status(400).json({
        error:
          "Shop name/slug and password are required."
      });
    }

    const cleanSlug = slugify(slug);

    const { data: business, error } =
      await supabase
        .from("businesses")
        .select("*")
        .eq("slug", cleanSlug)
        .maybeSingle();

    if (error) {
      console.error(error);

      return res.status(500).json({
        error: "Could not log in."
      });
    }

    if (!business) {
      return res.status(401).json({
        error: "Shop not found or incorrect password."
      });
    }

    const sellerPasswordCorrect =
      verifyPassword(
        String(password),
        business.password_hash
      );

    const adminPasswordCorrect =
      checkAdminPassword(password);

    if (
      !sellerPasswordCorrect &&
      !adminPasswordCorrect
    ) {
      return res.status(401).json({
        error: "Incorrect password."
      });
    }

    const token =
      createToken(business.id);

    return res.json({
      ok: true,
      token,
      business: {
        id: business.id,
        name: business.name,
        slug: business.slug,
        whatsapp: business.whatsapp,
        location: business.location,
        hours: business.hours,
        description: business.description,
        created_at: business.created_at
      }
    });
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      error: "Server error while logging in."
    });
  }
});

/* =========================================================
   SELLER DASHBOARD
========================================================= */

app.get("/api/me", requireAuth, async (req, res) => {
  try {
    const { data: products, error } =
      await supabase
        .from("products")
        .select("*")
        .eq("business_id", req.businessId)
        .order("created_at", {
          ascending: false
        });

    if (error) {
      console.error(error);

      return res.status(500).json({
        error: "Could not load products."
      });
    }

    return res.json({
      business: {
        id: req.business.id,
        name: req.business.name,
        slug: req.business.slug,
        whatsapp: req.business.whatsapp,
        location: req.business.location,
        hours: req.business.hours,
        description: req.business.description,
        created_at: req.business.created_at
      },
      products: products || []
    });
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      error: "Server error."
    });
  }
});

/* =========================================================
   ADD PRODUCT
========================================================= */

app.post("/api/products", requireAuth, async (req, res) => {
  try {
    const {
      name,
      price,
      image,
      description
    } = req.body;

    if (!name || price === undefined || price === "") {
      return res.status(400).json({
        error: "Product name and price are required."
      });
    }

    const numericPrice =
      Number(price);

    if (
      !Number.isFinite(numericPrice) ||
      numericPrice < 0
    ) {
      return res.status(400).json({
        error: "Please enter a valid price."
      });
    }

    const { data: product, error } =
      await supabase
        .from("products")
        .insert({
          business_id: req.businessId,
          name: String(name).trim(),
          price: numericPrice,
          image:
            String(image || "").trim(),
          description:
            String(description || "").trim()
        })
        .select("*")
        .single();

    if (error) {
      console.error(error);

      return res.status(500).json({
        error: "Could not add product."
      });
    }

    return res.status(201).json({
      ok: true,
      product
    });
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      error: "Server error while adding product."
    });
  }
});

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
        !Number.isFinite(numericPrice) ||
        numericPrice < 0
      ) {
        return res.status(400).json({
          error: "Please enter a valid price."
        });
      }

      const { data: product, error } =
        await supabase
          .from("products")
          .update({
            name: String(name).trim(),
            price: numericPrice,
            image:
              String(image || "").trim(),
            description:
              String(description || "").trim()
          })
          .eq("id", productId)
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
          error: "Product not found."
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

      const { data: deletedProduct, error } =
        await supabase
          .from("products")
          .delete()
          .eq("id", productId)
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
          error: "Product not found."
        });
      }

      return res.json({
        ok: true,
        message: "Product deleted successfully."
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
      const { error } =
        await supabase
          .from("businesses")
          .delete()
          .eq("id", req.businessId);

      if (error) {
        console.error(
          "Delete shop error:",
          error
        );

        return res.status(500).json({
          error:
            "Could not delete shop."
        });
      }

      return res.json({
        ok: true,
        message:
          "Shop deleted successfully."
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
        !checkAdminPassword(adminPassword)
      ) {
        return res.status(403).json({
          error:
            "Incorrect admin password."
        });
      }

      if (!slug || !newPassword) {
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
          String(newPassword)
        );

      const { data: business, error } =
        await supabase
          .from("businesses")
          .update({
            password_hash:
              passwordHash
          })
          .eq("slug", cleanSlug)
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
          error: "Shop not found."
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

app.get("/shop/:slug", (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      "public",
      "shop.html"
    )
  );
});

app.get("/seller", (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      "public",
      "seller.html"
    )
  );
});

app.get("*", (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      "public",
      "index.html"
    )
  );
});

/* =========================================================
   START SERVER
========================================================= */

app.listen(PORT, () => {
  console.log(
    `ShopLink Ghana running on port ${PORT}`
  );
});
