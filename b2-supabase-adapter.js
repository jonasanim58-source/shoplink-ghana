"use strict";

const crypto = require("crypto");

function createB2SupabaseAdapter(store) {
  function from(table) {
    const query = {
      table,
      action: "select",
      columns: "*",
      filters: [],
      orderBy: null,
      maxRows: null,
      payload: null,
      returning: false,
      singleMode: null,
      promise: null
    };

    function matches(row) {
      return query.filters.every(filter => {
        const actual = row[filter.column];
        const expected = filter.value;

        if (actual === expected) return true;
        if (actual == null || expected == null) return false;

        return String(actual) === String(expected);
      });
    }

    function project(row) {
      if (query.columns === "*") {
        return structuredClone(row);
      }

      const fields = query.columns
        .split(",")
        .map(field => field.trim())
        .filter(Boolean);

      const result = {};

      for (const field of fields) {
        if (Object.prototype.hasOwnProperty.call(row, field)) {
          result[field] = row[field];
        }
      }

      return result;
    }

    function arrange(rows) {
      let result = [...rows];

      if (query.orderBy) {
        const { column, ascending } = query.orderBy;

        result.sort((a, b) => {
          const first = a[column];
          const second = b[column];

          if (first == null && second == null) return 0;
          if (first == null) return ascending ? -1 : 1;
          if (second == null) return ascending ? 1 : -1;

          if (first < second) return ascending ? -1 : 1;
          if (first > second) return ascending ? 1 : -1;

          return 0;
        });
      }

      if (query.maxRows !== null) {
        result = result.slice(0, query.maxRows);
      }

      return result;
    }

    function formatResult(rows) {
      const result = arrange(rows).map(project);

      if (query.singleMode === "maybeSingle") {
        if (result.length > 1) {
          return {
            data: null,
            error: { message: "Multiple rows returned." }
          };
        }

        return {
          data: result[0] || null,
          error: null
        };
      }

      if (query.singleMode === "single") {
        if (result.length !== 1) {
          return {
            data: null,
            error: { message: "Expected exactly one row." }
          };
        }

        return {
          data: result[0],
          error: null
        };
      }

      return {
        data: result,
        error: null
      };
    }

    async function execute() {
      if (query.promise) return query.promise;

      query.promise = (async () => {
        try {
          const database = store.read();

          if (
            !["businesses", "products"].includes(query.table) ||
            !Array.isArray(database[query.table])
          ) {
            throw new Error("Unknown database table.");
          }

          if (query.action === "select") {
            const rows = database[query.table].filter(matches);
            return formatResult(rows);
          }

          const result = await store.update(draft => {
            const rows = draft[query.table];

            if (query.action === "insert") {
              const entries = Array.isArray(query.payload)
                ? query.payload
                : [query.payload];

              const inserted = [];

              for (const entry of entries) {
                const row = {
                  ...entry
                };

                row.id = row.id || crypto.randomUUID();

                row.created_at =
                  row.created_at || new Date().toISOString();

                if (
                  query.table === "businesses" &&
                  rows.some(item => item.slug === row.slug)
                ) {
                  throw new Error("Shop slug already exists.");
                }

                rows.push(row);
                inserted.push(row);
              }

              return query.returning
                ? arrange(inserted).map(project)
                : null;
            }

            if (query.action === "update") {
              const affected = [];

              for (const row of rows) {
                if (matches(row)) {
                  Object.assign(row, query.payload);
                  affected.push(row);
                }
              }

              return query.returning
                ? arrange(affected).map(project)
                : null;
            }

            if (query.action === "delete") {
              const affected = [];
              const remaining = [];

              for (const row of rows) {
                if (matches(row)) {
                  affected.push(row);
                } else {
                  remaining.push(row);
                }
              }

              draft[query.table] = remaining;

              return query.returning
                ? arrange(affected).map(project)
                : null;
            }

            throw new Error("Unsupported database operation.");
          });

          if (!query.returning) {
            return {
              data: null,
              error: null
            };
          }

          if (query.singleMode === "maybeSingle") {
            if (result.length > 1) {
              return {
                data: null,
                error: { message: "Multiple rows returned." }
              };
            }

            return {
              data: result[0] || null,
              error: null
            };
          }

          if (query.singleMode === "single") {
            if (result.length !== 1) {
              return {
                data: null,
                error: { message: "Expected exactly one row." }
              };
            }

            return {
              data: result[0],
              error: null
            };
          }

          return {
            data: result,
            error: null
          };

        } catch (error) {
          console.error("B2 adapter error:", error);

          return {
            data: null,
            error: {
              message: error.message || "Database operation failed."
            }
          };
        }
      })();

      return query.promise;
    }

    const builder = {
      select(columns = "*") {
        query.columns = columns;

        if (query.action !== "select") {
          query.returning = true;
        }

        return builder;
      },

      insert(payload) {
        query.action = "insert";
        query.payload = payload;
        return builder;
      },

      update(payload) {
        query.action = "update";
        query.payload = payload;
        return builder;
      },

      delete() {
        query.action = "delete";
        return builder;
      },

      eq(column, value) {
        query.filters.push({ column, value });
        return builder;
      },

      order(column, options = {}) {
        query.orderBy = {
          column,
          ascending: options.ascending !== false
        };

        return builder;
      },

      limit(value) {
        query.maxRows = Math.max(0, Number(value));
        return builder;
      },

      single() {
        query.singleMode = "single";
        return builder;
      },

      maybeSingle() {
        query.singleMode = "maybeSingle";
        return builder;
      },

      then(resolve, reject) {
        return execute().then(resolve, reject);
      },

      catch(reject) {
        return execute().catch(reject);
      },

      finally(callback) {
        return execute().finally(callback);
      }
    };

    return builder;
  }

  async function deleteBusinessAndProducts(businessId) {
    return store.update(draft => {
      const exists = draft.businesses.some(
        business => business.id === businessId
      );

      if (!exists) {
        return false;
      }

      draft.products = draft.products.filter(
        product => product.business_id !== businessId
      );

      draft.businesses = draft.businesses.filter(
        business => business.id !== businessId
      );

      return true;
    });
  }

  return {
    from,
    deleteBusinessAndProducts
  };
}

module.exports = createB2SupabaseAdapter;
