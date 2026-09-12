const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const DB = path.join(__dirname, "data.json");

const AUTH_SECRET =
  process.env.AUTH_SECRET || "shoplink-change-this-secret";

const ADMIN_PASSWORD =
  process.env.SHOPLINK_ADMIN_PASSWORD || "";

app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));


/* =========================
   DATABASE
========================= */

function load() {

  if (!fs.existsSync(DB)) {

    fs.writeFileSync(
      DB,
      JSON.stringify(
        {
          businesses: [
            {
              id: "demo",
              name: "Adwoa Fashion Hub",
              slug: "adwoa-fashion",
              whatsapp: "233241234567",
              location: "Kumasi, Ghana",
              hours: "Mon–Sat, 8 AM–7 PM",
              description:
                "Fashion, accessories and everyday essentials."
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
        },
        null,
        2
      )
    );
  }

  return JSON.parse(fs.readFileSync(DB, "utf8"));
}


function save(data) {
  fs.writeFileSync(DB, JSON.stringify(data, null, 2));
}


function id() {
  return crypto.randomBytes(16).toString("hex");
}


function slugify(s) {

  return s
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 50);
}


/* =========================
   PASSWORD HELPERS
========================= */

function hashPassword(password) {

  const salt = crypto.randomBytes(16).toString("hex");

  const hash = crypto
    .scryptSync(password, salt, 64)
    .toString("hex");

  return `${salt}:${hash}`;
}


function verifyPassword(password, stored) {

  try {

    const parts = stored.split(":");

    if (parts.length !== 2) return false;

    const salt = parts[0];
    const storedHash = parts[1];

    const hash = crypto.scryptSync(
      password,
      salt,
      64
    ).toString("hex");

    return crypto.timingSafeEqual(
      Buffer.from(hash, "hex"),
      Buffer.from(storedHash, "hex")
    );

  } catch {

    return false;
  }
}


/* =========================
   LOGIN TOKEN
========================= */

function createToken(businessId) {

  const payload = {
    businessId,
    exp: Date.now() + 1000 * 60 * 60 * 24 * 7
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

    if (!token) return null;

    const parts = token.split(".");

    if (parts.length !== 2) return null;

    const encoded = parts[0];
    const signature = parts[1];

    const expected = crypto
      .createHmac("sha256", AUTH_SECRET)
      .update(encoded)
      .digest("base64url");

    if (
      signature.length !== expected.length ||
      !crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expected)
      )
    ) {
      return null;
    }

    const payload = JSON.parse(
      Buffer.from(encoded, "base64url").toString()
    );

    if (!payload.businessId) return null;

    if (payload.exp < Date.now()) return null;

    return payload;

  } catch {

    return null;
  }
}


function getToken(req) {

  const auth = req.headers.authorization || "";

  if (auth.startsWith("Bearer ")) {
    return auth.substring(7);
  }

  return null;
}


function requireAuth(req, res, next) {

  const token = getToken(req);
  const payload = verifyToken(token);

  if (!payload) {

    return res
      .status(401)
      .json({
        error: "Seller login required."
      });
  }

  req.businessId = payload.businessId;

  next();
}


/* =========================
   PUBLIC SHOP
========================= */

app.get(
  "/api/business/:slug",
  (req, res) => {

    const data = load();

    const business =
      data.businesses.find(
        x => x.slug === req.params.slug
      );

    if (!business) {

      return res
        .status(404)
        .json({
          error: "Shop not found"
        });
    }

    res.json({
      business,
      products: data.products.filter(
        x => x.businessId === business.id
      )
    });
  }
);


/* =========================
   CREATE BUSINESS
========================= */

app.post(
  "/api/businesses",
  (req, res) => {

    const {
      name,
      whatsapp,
      location,
      hours,
      description,
      password
    } = req.body || {};

    if (!name || !whatsapp) {

      return res
        .status(400)
        .json({
          error:
            "Business name and WhatsApp number are required."
        });
    }

    if (!password || password.length < 6) {

      return res
        .status(400)
        .json({
          error:
            "Seller password must be at least 6 characters."
        });
    }

    const data = load();

    let slug =
      slugify(name) || "shop";

    const base = slug;
    let number = 2;

    while (
      data.businesses.some(
        x => x.slug === slug
      )
    ) {

      slug =
        base + "-" + number++;

    }

    const business = {

      id: id(),

      name,

      slug,

      whatsapp:
        String(whatsapp).replace(/\D/g, ""),

      location:
        location || "Ghana",

      hours:
        hours || "Contact seller",

      description:
        description || "",

      passwordHash:
        hashPassword(password),

      createdAt:
        new Date().toISOString()
    };

    data.businesses.push(business);

    save(data);

    const token =
      createToken(business.id);

    res.json({
      ok: true,
      business,
      token,
      shopUrl:
        "/shop/" + business.slug
    });
  }
);


/* =========================
   SELLER LOGIN
========================= */

app.post(
  "/api/login",
  (req, res) => {

    const {
      slug,
      password
    } = req.body || {};

    if (!slug || !password) {

      return res
        .status(400)
        .json({
          error:
            "Shop link and password are required."
        });
    }

    const data = load();

    const business =
      data.businesses.find(
        x => x.slug === slug
      );

    if (!business) {

      return res
        .status(401)
        .json({
          error:
            "Shop not found."
        });
    }


    let valid = false;


    /* Existing shops created before
       password protection can use the
       Render admin password. */

    if (
      business.passwordHash &&
      verifyPassword(
        password,
        business.passwordHash
      )
    ) {

      valid = true;

    } else if (
      ADMIN_PASSWORD &&
      password === ADMIN_PASSWORD
    ) {

      valid = true;

    }


    if (!valid) {

      return res
        .status(401)
        .json({
          error:
            "Incorrect password."
        });
    }


    const token =
      createToken(business.id);

    res.json({
      ok: true,
      token,
      business
    });
  }
);


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
        x => x.id === req.businessId
      );

    if (!business) {

      return res
        .status(404)
        .json({
          error:
            "Business not found."
        });
    }

    res.json({
      business,
      products:
        data.products.filter(
          x =>
            x.businessId ===
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

    const data = load();

    const business =
      data.businesses.find(
        x => x.id === req.businessId
      );

    if (!business) {

      return res
        .status(404)
        .json({
          error:
            "Business not found."
        });
    }

    if (!name || !price) {

      return res
        .status(400)
        .json({
          error:
            "Product name and price are required."
        });
    }

    const product = {

      id: id(),

      businessId:
        business.id,

      name,

      price:
        Number(price),

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

    const data = load();

    const product =
      data.products.find(
        x =>
          x.id === req.params.id &&
          x.businessId ===
            req.businessId
      );

    if (!product) {

      return res
        .status(404)
        .json({
          error:
            "Product not found."
        });
    }

    const {
      name,
      price,
      image,
      description
    } = req.body || {};

    if (!name || !price) {

      return res
        .status(400)
        .json({
          error:
            "Product name and price are required."
        });
    }

    product.name = name;

    product.price =
      Number(price);

    product.image =
      image || product.image;

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
        x =>
          x.id === req.params.id &&
          x.businessId ===
            req.businessId
      );

    if (index === -1) {

      return res
        .status(404)
        .json({
          error:
            "Product not found."
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
  (req, res) =>
    res.sendFile(
      path.join(
        __dirname,
        "public",
        "shop.html"
      )
    )
);


app.get(
  "/seller",
  (req, res) =>
    res.sendFile(
      path.join(
        __dirname,
        "public",
        "seller.html"
      )
    )
);


app.get(
  "*splat",
  (req, res) =>
    res.sendFile(
      path.join(
        __dirname,
        "public",
        "index.html"
      )
    )
);


app.listen(
  PORT,
  () =>
    console.log(
      "ShopLink Ghana V3 running on port " +
        PORT
    )
);
