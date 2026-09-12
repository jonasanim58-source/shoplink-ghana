const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;
const DB = path.join(__dirname, "data.json");

const AUTH_SECRET =
  process.env.AUTH_SECRET || "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET";

const ADMIN_PASSWORD =
  process.env.SHOPLINK_ADMIN_PASSWORD || "";

app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

/* =========================
   DATABASE
========================= */

function load() {
  if (!fs.existsSync(DB)) {
    const initialData = {
      businesses: [
        {
          id: "demo",
          name: "Adwoa Fashion Hub",
          slug: "adwoa-fashion",
          whatsapp: "233241234567",
          location: "Kumasi, Ghana",
          hours: "Mon–Sat, 8 AM–7 PM",
          description:
            "Fashion, accessories and everyday essentials.",
          passwordHash: ""
        }
      ],

      products: [
        {
          id: "p1",
          businessId: "demo",
          name: "Classic Sneakers",
          price: 180,
          image:
            "https://images.unsplash.com/photo-1542291026-7eec264c27ff?auto=format&fit=crop&w=700&q=80",
          description:
            "Comfortable everyday sneakers."
        },
        {
          id: "p2",
          businessId: "demo",
          name: "Premium Handbag",
          price: 220,
          image:
            "https://images.unsplash.com/photo-1584917865442-de89df76afd3?auto=format&fit=crop&w=700&q=80",
          description:
            "Elegant handbag."
        },
        {
          id: "p3",
          businessId: "demo",
          name: "Perfume Spray",
          price: 120,
          image:
            "https://images.unsplash.com/photo-1541643600914-78b084683601?auto=format&fit=crop&w=700&q=80",
          description:
            "Fresh everyday fragrance."
        }
      ]
    };

    fs.writeFileSync(
      DB,
      JSON.stringify(initialData, null, 2)
    );
  }

  return JSON.parse(
    fs.readFileSync(DB, "utf8")
  );
}

function save(data) {
  fs.writeFileSync(
    DB,
    JSON.stringify(data, null, 2)
  );
}

/* =========================
   HELPERS
========================= */

function createId() {
  return crypto.randomBytes(16).toString("hex");
}

function slugify(value) {
  return String(value)
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 50);
}

/* =========================
   PASSWORD SECURITY
========================= */

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");

  const hash = crypto
    .scryptSync(String(password), salt, 64)
    .toString("hex");

  return `${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {
  try {
    if (!storedHash) {
      return false;
    }

    const parts = storedHash.split(":");

    if (parts.length !== 2) {
      return false;
    }

    const salt = parts[0];
    const savedHash = parts[1];

    const calculatedHash = crypto
      .scryptSync(String(password), salt, 64)
      .toString("hex");

    const a = Buffer.from(calculatedHash, "hex");
    const b = Buffer.from(savedHash, "hex");

    if (a.length !== b.length) {
      return false;
    }

    return crypto.timingSafeEqual(a, b);
  } catch (error) {
    return false;
  }
}

/* =========================
   TOKEN
========================= */

function createToken(businessId) {
  const payload = {
    businessId: businessId,
    expires: Date.now() + 24 * 60 * 60 * 1000
  };

  const encoded = Buffer
    .from(JSON.stringify(payload))
    .toString("base64url");

  const signature = crypto
    .createHmac("sha256", AUTH_SECRET)
    .update(encoded)
    .digest("base64url");

  return `${encoded}.${signature}`;
}

function verifyToken(token) {
  try {
    if (!token) {
      return null;
    }

    const parts = token.split(".");

    if (parts.length !== 2) {
      return null;
    }

    const encoded = parts[0];
    const signature = parts[1];

    const expectedSignature = crypto
      .createHmac("sha256", AUTH_SECRET)
      .update(encoded)
      .digest("base64url");

    const a = Buffer.from(signature);
    const b = Buffer.from(expectedSignature);

    if (a.length !== b.length) {
      return null;
    }

    if (!crypto.timingSafeEqual(a, b)) {
      return null;
    }

    const payload = JSON.parse(
      Buffer.from(encoded, "base64url").toString("utf8")
    );

    if (!payload.businessId) {
      return null;
    }

    if (payload.expires < Date.now()) {
      return null;
    }

    return payload;
  } catch (error) {
    return null;
  }
}

function getToken(req) {
  const authorization =
    req.headers.authorization || "";

  if (!authorization.startsWith("Bearer ")) {
    return null;
  }

  return authorization.substring(7);
}

function requireAuth(req, res, next) {
  const token = getToken(req);
  const payload = verifyToken(token);

  if (!payload) {
    return res.status(401).json({
      error: "Seller login required."
    });
  }

  const data = load();

  const business = data.businesses.find(
    (item) => item.id === payload.businessId
  );

  if (!business) {
    return res.status(401).json({
      error: "Business no longer exists."
    });
  }

  req.businessId = business.id;

  next();
}

/* =========================
   PUBLIC SHOP
========================= */

app.get("/api/business/:slug", (req, res) => {
  const data = load();

  const business = data.businesses.find(
    (item) => item.slug === req.params.slug
  );

  if (!business) {
    return res.status(404).json({
      error: "Shop not found."
    });
  }

  res.json({
    business: {
      id: business.id,
      name: business.name,
      slug: business.slug,
      whatsapp: business.whatsapp,
      location: business.location,
      hours: business.hours,
      description: business.description
    },

    products: data.products.filter(
      (item) => item.businessId === business.id
    )
  });
});

/* =========================
   CREATE SHOP
========================= */

app.post("/api/businesses", (req, res) => {
  const {
    name,
    whatsapp,
    location,
    hours,
    description,
    password
  } = req.body || {};

  if (!name || !whatsapp) {
    return res.status(400).json({
      error:
        "Business name and WhatsApp number are required."
    });
  }

  if (!password) {
    return res.status(400).json({
      error: "Password is required."
    });
  }

  if (String(password).length < 6) {
    return res.status(400).json({
      error:
        "Password must be at least 6 characters."
    });
  }

  const data = load();

  let slug = slugify(name) || "shop";

  const baseSlug = slug;

  let number = 2;

  while (
    data.businesses.some(
      (item) => item.slug === slug
    )
  ) {
    slug = `${baseSlug}-${number}`;
    number++;
  }

  const business = {
    id: createId(),
    name: String(name).trim(),
    slug: slug,
    whatsapp: String(whatsapp).replace(/\D/g, ""),
    location:
      location || "Ghana",
    hours:
      hours || "Contact seller",
    description:
      description || "",
    passwordHash:
      hashPassword(String(password)),
    createdAt:
      new Date().toISOString()
  };

  data.businesses.push(business);

  save(data);

  /*
    IMPORTANT:
    We DO NOT automatically create a login token here.
    The seller must actually log in using the password.
  */

  res.json({
    ok: true,

    business: {
      id: business.id,
      name: business.name,
      slug: business.slug,
      whatsapp: business.whatsapp,
      location: business.location,
      hours: business.hours,
      description: business.description
    },

    shopUrl:
      `/shop/${business.slug}`
  });
});

/* =========================
   LOGIN
========================= */

app.post("/api/login", (req, res) => {
  const {
    slug,
    password
  } = req.body || {};

  if (!slug || !password) {
    return res.status(400).json({
      error:
        "Shop slug and password are required."
    });
  }

  const data = load();

  const business = data.businesses.find(
    (item) =>
      item.slug ===
      String(slug).trim().toLowerCase()
  );

  if (!business) {
    return res.status(401).json({
      error:
        "Incorrect shop or password."
    });
  }

  /*
    Normal seller password
  */

  if (
    business.passwordHash &&
    verifyPassword(
      String(password),
      business.passwordHash
    )
  ) {
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
        description: business.description
      }
    });
  }

  /*
    Platform owner emergency/admin password.

    This only works if you deliberately set
    SHOPLINK_ADMIN_PASSWORD in Render.
  */

  if (
    ADMIN_PASSWORD &&
    String(password) ===
      String(ADMIN_PASSWORD)
  ) {
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
        description: business.description
      }
    });
  }

  return res.status(401).json({
    error:
      "Incorrect shop or password."
  });
});

/* =========================
   RESET EXISTING SHOP PASSWORD
========================= */

/*
   This is for shops created before the
   new password system, such as Accra Style Hub.

   You must provide your private
   SHOPLINK_ADMIN_PASSWORD.
*/

app.post("/api/admin/reset-password", (req, res) => {
  const {
    adminPassword,
    slug,
    newPassword
  } = req.body || {};

  if (!ADMIN_PASSWORD) {
    return res.status(500).json({
      error:
        "SHOPLINK_ADMIN_PASSWORD is not configured in Render."
    });
  }

  if (
    !adminPassword ||
    String(adminPassword) !==
      String(ADMIN_PASSWORD)
  ) {
    return res.status(401).json({
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

  if (String(newPassword).length < 6) {
    return res.status(400).json({
      error:
        "New password must be at least 6 characters."
    });
  }

  const data = load();

  const business = data.businesses.find(
    (item) =>
      item.slug ===
      String(slug).trim().toLowerCase()
  );

  if (!business) {
    return res.status(404).json({
      error: "Shop not found."
    });
  }

  business.passwordHash =
    hashPassword(
      String(newPassword)
    );

  save(data);

  res.json({
    ok: true,
    message:
      "Shop password successfully reset."
  });
});

/* =========================
   CURRENT SELLER
========================= */

app.get(
  "/api/me",
  requireAuth,
  (req, res) => {
    const data = load();

    const business =
      data.businesses.find(
        (item) =>
          item.id === req.businessId
      );

    if (!business) {
      return res.status(404).json({
        error: "Business not found."
      });
    }

    res.json({
      business: {
        id: business.id,
        name: business.name,
        slug: business.slug,
        whatsapp: business.whatsapp,
        location: business.location,
        hours: business.hours,
        description: business.description
      },

      products:
        data.products.filter(
          (item) =>
            item.businessId ===
            business.id
        )
    });
  }
);

/* =========================
   ADD PRODUCT
========================= */

app.post(
  "/api/products",
  requireAuth,
  (req, res) => {
    const {
      name,
      price,
      image,
      description
    } = req.body || {};

    if (!name || price === undefined || price === "") {
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
        error:
          "Please enter a valid price."
      });
    }

    const data = load();

    const business =
      data.businesses.find(
        (item) =>
          item.id === req.businessId
      );

    if (!business) {
      return res.status(404).json({
        error: "Business not found."
      });
    }

    const product = {
      id: createId(),
      businessId: business.id,
      name: String(name).trim(),
      price: numericPrice,

      image:
        image ||
        "https://images.unsplash.com/photo-1523275335684-37898b6baf30?auto=format&fit=crop&w=700&q=80",

      description:
        description || ""
    };

    data.products.push(product);

    save(data);

    res.json({
      ok: true,
      product
    });
  }
);

/* =========================
   EDIT PRODUCT
========================= */

app.put(
  "/api/products/:id",
  requireAuth,
  (req, res) => {
    const {
      name,
      price,
      image,
      description
    } = req.body || {};

    if (!name || price === undefined || price === "") {
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
        error:
          "Please enter a valid price."
      });
    }

    const data = load();

    const product =
      data.products.find(
        (item) =>
          item.id === req.params.id &&
          item.businessId ===
            req.businessId
      );

    if (!product) {
      return res.status(404).json({
        error: "Product not found."
      });
    }

    product.name =
      String(name).trim();

    product.price =
      numericPrice;

    if (image) {
      product.image =
        String(image).trim();
    }

    product.description =
      description || "";

    save(data);

    res.json({
      ok: true,
      product
    });
  }
);

/* =========================
   DELETE PRODUCT
========================= */

app.delete(
  "/api/products/:id",
  requireAuth,
  (req, res) => {
    const data = load();

    const index =
      data.products.findIndex(
        (item) =>
          item.id === req.params.id &&
          item.businessId ===
            req.businessId
      );

    if (index === -1) {
      return res.status(404).json({
        error: "Product not found."
      });
    }

    data.products.splice(index, 1);

    save(data);

    res.json({
      ok: true
    });
  }
);

/* =========================
   PAGES
========================= */

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

app.get(
  "*splat",
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

/* =========================
   START SERVER
========================= */

app.listen(
  PORT,
  () => {
    console.log(
      "ShopLink Ghana V4 running on port " +
        PORT
    );
  }
);
