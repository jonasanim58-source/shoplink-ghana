const express = require("express");
const path = require("path");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();

const PORT = process.env.PORT || 10000;

/* =========================
   ENVIRONMENT VARIABLES
========================= */

const SUPABASE_URL =
  process.env.SUPABASE_URL;

const SUPABASE_SERVICE_ROLE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY;

const AUTH_SECRET =
  process.env.AUTH_SECRET;

const ADMIN_PASSWORD =
  process.env.SHOPLINK_ADMIN_PASSWORD || "";


/* =========================
   CHECK CONFIGURATION
========================= */

if (!SUPABASE_URL) {
  console.error(
    "ERROR: SUPABASE_URL is missing."
  );
}

if (!SUPABASE_SERVICE_ROLE_KEY) {
  console.error(
    "ERROR: SUPABASE_SERVICE_ROLE_KEY is missing."
  );
}

if (!AUTH_SECRET) {
  console.error(
    "ERROR: AUTH_SECRET is missing."
  );
}


/* =========================
   SUPABASE
========================= */

const supabase = createClient(
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
      detectSessionInUrl: false
    }
  }
);


/* =========================
   EXPRESS
========================= */

app.use(
  express.json({
    limit: "1mb"
  })
);

app.use(
  express.static(
    path.join(__dirname, "public")
  )
);


/* =========================
   BASIC HELPERS
========================= */

function createId() {
  return crypto
    .randomBytes(16)
    .toString("hex");
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
   PASSWORD HASHING
========================= */

function hashPassword(password) {

  const salt =
    crypto
      .randomBytes(16)
      .toString("hex");

  const hash =
    crypto
      .scryptSync(
        String(password),
        salt,
        64
      )
      .toString("hex");

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
      storedHash.split(":");

    if (parts.length !== 2) {
      return false;
    }

    const salt = parts[0];

    const savedHash =
      parts[1];

    const calculatedHash =
      crypto
        .scryptSync(
          String(password),
          salt,
          64
        )
        .toString("hex");

    const a =
      Buffer.from(
        calculatedHash,
        "hex"
      );

    const b =
      Buffer.from(
        savedHash,
        "hex"
      );

    if (a.length !== b.length) {
      return false;
    }

    return crypto.timingSafeEqual(
      a,
      b
    );

  } catch (error) {

    console.error(
      "Password verification error:",
      error
    );

    return false;
  }
}


/* =========================
   TOKEN SYSTEM
========================= */

function createToken(
  businessId
) {

  const payload = {

    businessId,

    expires:
      Date.now() +
      24 * 60 * 60 * 1000

  };

  const encoded =
    Buffer
      .from(
        JSON.stringify(payload)
      )
      .toString("base64url");

  const signature =
    crypto
      .createHmac(
        "sha256",
        AUTH_SECRET
      )
      .update(encoded)
      .digest("base64url");

  return (
    encoded +
    "." +
    signature
  );
}


function verifyToken(token) {

  try {

    if (!token) {
      return null;
    }

    const parts =
      token.split(".");

    if (parts.length !== 2) {
      return null;
    }

    const encoded =
      parts[0];

    const signature =
      parts[1];

    const expected =
      crypto
        .createHmac(
          "sha256",
          AUTH_SECRET
        )
        .update(encoded)
        .digest("base64url");

    const a =
      Buffer.from(signature);

    const b =
      Buffer.from(expected);

    if (a.length !== b.length) {
      return null;
    }

    if (
      !crypto.timingSafeEqual(
        a,
        b
      )
    ) {
      return null;
    }

    const payload =
      JSON.parse(
        Buffer
          .from(
            encoded,
            "base64url"
          )
          .toString("utf8")
      );

    if (!payload.businessId) {
      return null;
    }

    if (
      payload.expires <
      Date.now()
    ) {
      return null;
    }

    return payload;

  } catch (error) {

    return null;
  }
}


function getToken(req) {

  const authorization =
    req.headers.authorization ||
    "";

  if (
    !authorization.startsWith(
      "Bearer "
    )
  ) {
    return null;
  }

  return authorization.substring(
    7
  );
}


/* =========================
   AUTH MIDDLEWARE
========================= */

async function requireAuth(
  req,
  res,
  next
) {

  try {

    const token =
      getToken(req);

    const payload =
      verifyToken(token);

    if (!payload) {

      return res.status(401).json({
        error:
          "Seller login required."
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
          payload.businessId
        )
        .maybeSingle();


    if (error) {

      console.error(
        "Auth database error:",
        error
      );

      return res.status(500).json({
        error:
          "Database error."
      });
    }


    if (!business) {

      return res.status(401).json({
        error:
          "Business no longer exists."
      });
    }


    req.business =
      business;

    req.businessId =
      business.id;

    next();

  } catch (error) {

    console.error(
      "Authentication error:",
      error
    );

    res.status(500).json({
      error:
        "Authentication failed."
    });
  }
}


/* =========================
   PUBLIC SHOP
========================= */

app.get(
  "/api/business/:slug",
  async (req, res) => {

    try {

      const {
        data: business,
        error:
          businessError
      } =
        await supabase
          .from("businesses")
          .select(
            "id,name,slug,whatsapp,location,hours,description,created_at"
          )
          .eq(
            "slug",
            req.params.slug
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
        error:
          productError
      } =
        await supabase
          .from("products")
          .select("*")
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


      if (productError) {

        console.error(
          productError
        );

        return res.status(500).json({
          error:
            "Could not load products."
        });
      }


      res.json({
        business,
        products:
          products || []
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Server error."
      });
    }
  }
);


/* =========================
   CREATE SHOP
========================= */

app.post(
  "/api/businesses",
  async (req, res) => {

    try {

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
          error:
            "Password is required."
        });
      }


      if (
        String(password).length < 6
      ) {

        return res.status(400).json({
          error:
            "Password must be at least 6 characters."
        });
      }


      let slug =
        slugify(name) ||
        "shop";


      const {
        data: existing,
        error:
          existingError
      } =
        await supabase
          .from("businesses")
          .select("slug")
          .ilike(
            "slug",
            `${slug}%`
          );


      if (existingError) {

        console.error(
          existingError
        );

        return res.status(500).json({
          error:
            "Could not check shop name."
        });
      }


      const existingSlugs =
        new Set(
          (existing || [])
            .map(
              item => item.slug
            )
        );


      const originalSlug =
        slug;

      let number = 2;

      while (
        existingSlugs.has(slug)
      ) {

        slug =
          `${originalSlug}-${number}`;

        number++;
      }


      const business = {

        id: createId(),

        name:
          String(name).trim(),

        slug,

        whatsapp:
          String(whatsapp)
            .replace(/\D/g, ""),

        location:
          location ||
          "Ghana",

        hours:
          hours ||
          "Contact seller",

        description:
          description ||
          "",

        password_hash:
          hashPassword(
            String(password)
          )

      };


      const {
        data: created,
        error
      } =
        await supabase
          .from("businesses")
          .insert(
            business
          )
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
            "Could not create shop: " +
            error.message
        });
      }


      /*
        IMPORTANT:
        We intentionally DO NOT
        log the seller in here.
      */

      res.json({

        ok: true,

        business:
          created,

        shopUrl:
          "/shop/" +
          created.slug

      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Server error while creating shop."
      });
    }
  }
);


/* =========================
   SELLER LOGIN
========================= */

app.post(
  "/api/login",
  async (req, res) => {

    try {

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


      const {
        data: business,
        error
      } =
        await supabase
          .from("businesses")
          .select("*")
          .eq(
            "slug",
            String(slug)
              .trim()
              .toLowerCase()
          )
          .maybeSingle();


      if (error) {

        console.error(
          error
        );

        return res.status(500).json({
          error:
            "Database error."
        });
      }


      if (!business) {

        return res.status(401).json({
          error:
            "Incorrect shop or password."
        });
      }


      let valid =
        verifyPassword(
          String(password),
          business.password_hash
        );


      /*
        Optional platform-owner password.
        This is NOT the normal seller password.
      */

      if (
        !valid &&
        ADMIN_PASSWORD &&
        String(password) ===
          String(ADMIN_PASSWORD)
      ) {

        valid = true;
      }


      if (!valid) {

        return res.status(401).json({
          error:
            "Incorrect shop or password."
        });
      }


      const token =
        createToken(
          business.id
        );


      res.json({

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
            business.description

        }

      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Login failed."
      });
    }
  }
);


/* =========================
   CURRENT SELLER
========================= */

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

        console.error(
          error
        );

        return res.status(500).json({
          error:
            "Could not load products."
        });
      }


      res.json({

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
            req.business.description

        },

        products:
          products || []

      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Could not load seller dashboard."
      });
    }
  }
);


/* =========================
   ADD PRODUCT
========================= */

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
      } = req.body || {};


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


      const product = {

        id:
          createId(),

        business_id:
          req.businessId,

        name:
          String(name).trim(),

        price:
          numericPrice,

        image:
          image ||
          "https://images.unsplash.com/photo-1523275335684-37898b6baf30?auto=format&fit=crop&w=700&q=80",

        description:
          description || ""

      };


      const {
        data: created,
        error
      } =
        await supabase
          .from("products")
          .insert(
            product
          )
          .select("*")
          .single();


      if (error) {

        console.error(
          "Add product error:",
          error
        );

        return res.status(500).json({
          error:
            "Could not add product: " +
            error.message
        });
      }


      res.json({

        ok: true,

        product:
          created

      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Server error."
      });
    }
  }
);


/* =========================
   EDIT PRODUCT
========================= */

app.put(
  "/api/products/:id",
  requireAuth,
  async (req, res) => {

    try {

      const {
        name,
        price,
        image,
        description
      } = req.body || {};


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
        data: existing,
        error:
          existingError
      } =
        await supabase
          .from("products")
          .select("*")
          .eq(
            "id",
            req.params.id
          )
          .eq(
            "business_id",
            req.businessId
          )
          .maybeSingle();


      if (existingError) {

        console.error(
          existingError
        );

        return res.status(500).json({
          error:
            "Could not find product."
        });
      }


      if (!existing) {

        return res.status(404).json({
          error:
            "Product not found."
        });
      }


      const {
        data: updated,
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
              image ||
              existing.image,

            description:
              description || ""

          })
          .eq(
            "id",
            req.params.id
          )
          .eq(
            "business_id",
            req.businessId
          )
          .select("*")
          .single();


      if (error) {

        console.error(
          error
        );

        return res.status(500).json({
          error:
            "Could not update product."
        });
      }


      res.json({

        ok: true,

        product:
          updated

      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Server error."
      });
    }
  }
);


/* =========================
   DELETE PRODUCT
========================= */

app.delete(
  "/api/products/:id",
  requireAuth,
  async (req, res) => {

    try {

      const {
        data: deleted,
        error
      } =
        await supabase
          .from("products")
          .delete()
          .eq(
            "id",
            req.params.id
          )
          .eq(
            "business_id",
            req.businessId
          )
          .select("id");


      if (error) {

        console.error(
          error
        );

        return res.status(500).json({
          error:
            "Could not delete product."
        });
      }


      if (
        !deleted ||
        deleted.length === 0
      ) {

        return res.status(404).json({
          error:
            "Product not found."
        });
      }


      res.json({
        ok: true
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Server error."
      });
    }
  }
);


/* =========================
   ADMIN RESET PASSWORD
========================= */

app.post(
  "/api/admin/reset-password",
  async (req, res) => {

    try {

      const {
        adminPassword,
        slug,
        newPassword
      } = req.body || {};


      if (!ADMIN_PASSWORD) {

        return res.status(500).json({
          error:
            "SHOPLINK_ADMIN_PASSWORD is not configured."
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


      const {
        data: business,
        error:
          findError
      } =
        await supabase
          .from("businesses")
          .select("id,name,slug")
          .eq(
            "slug",
            String(slug)
              .trim()
              .toLowerCase()
          )
          .maybeSingle();


      if (findError) {

        console.error(
          findError
        );

        return res.status(500).json({
          error:
            "Database error."
        });
      }


      if (!business) {

        return res.status(404).json({
          error:
            "Shop not found."
        });
      }


      const {
        error: updateError
      } =
        await supabase
          .from("businesses")
          .update({

            password_hash:
              hashPassword(
                String(newPassword)
              )

          })
          .eq(
            "id",
            business.id
          );


      if (updateError) {

        console.error(
          updateError
        );

        return res.status(500).json({
          error:
            "Could not reset password."
        });
      }


      res.json({

        ok: true,

        message:
          "Password successfully reset."

      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Server error."
      });
    }
  }
);


/* =========================
   PUBLIC PAGES
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
   START
========================= */

app.listen(
  PORT,
  () => {

    console.log(
      "ShopLink Ghana V5 running on port " +
      PORT
    );

  }
);
