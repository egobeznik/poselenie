const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
};

export default {
  async fetch(request, env) {

    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: corsHeaders
      });
    }

    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/") {
      return json({
        success: true,
        service: "poselenie-api",
        status: "online"
      });
    }

    if (
      request.method === "GET" &&
      url.pathname === "/debug/config"
    ) {
      return json({
        telegramBotToken: {
          exists: typeof env.TELEGRAM_BOT_TOKEN === "string",
          hasValue: Boolean(env.TELEGRAM_BOT_TOKEN),
          length: typeof env.TELEGRAM_BOT_TOKEN === "string"
            ? env.TELEGRAM_BOT_TOKEN.length
            : 0
        },
        supabaseSecretKey: {
          exists: typeof env.SUPABASE_SECRET_KEY === "string",
          hasValue: Boolean(env.SUPABASE_SECRET_KEY),
          length: typeof env.SUPABASE_SECRET_KEY === "string"
            ? env.SUPABASE_SECRET_KEY.length
            : 0
        },
        supabaseUrl: {
          exists: typeof env.SUPABASE_URL === "string",
          hasValue: Boolean(env.SUPABASE_URL),
          length: typeof env.SUPABASE_URL === "string"
            ? env.SUPABASE_URL.length
            : 0
        }
      });
    }

    if (request.method !== "POST") {
      return json({
        success: false,
        error: "Method not allowed"
      }, 405);
    }

    try {
      const body = await request.json();

      if (!body || !body.initData) {
        return json({
          success: false,
          error: "Telegram initData is required"
        }, 400);
      }

      if (!env.TELEGRAM_BOT_TOKEN) {
        return json({
          success: false,
          error: "TELEGRAM_BOT_TOKEN is missing"
        }, 500);
      }

      if (!env.SUPABASE_URL) {
        return json({
          success: false,
          error: "SUPABASE_URL is missing"
        }, 500);
      }

      if (!env.SUPABASE_SECRET_KEY) {
        return json({
          success: false,
          error: "SUPABASE_SECRET_KEY is missing"
        }, 500);
      }

      const telegramUser =
        await validateTelegramInitData(
          body.initData,
          env.TELEGRAM_BOT_TOKEN
        );

      if (!telegramUser) {
        return json({
          success: false,
          error: "Invalid Telegram authentication"
        }, 401);
      }

      if (url.pathname === "/auth") {
        return json({
          success: true,

          user: {
            id: telegramUser.id,
            username:
              telegramUser.username ?? null,

            first_name:
              telegramUser.first_name ?? null,

            last_name:
              telegramUser.last_name ?? null,

            photo_url:
              telegramUser.photo_url ?? null
          }
        });
      }

      if (url.pathname === "/player") {
        const player =
          await getOrCreatePlayer(
            telegramUser,
            env
          );

        return json({
          success: true,

          player: {
            id: player.id,
            telegram_id: player.telegram_id,
            username: player.username,
            first_name: player.first_name,
            last_name: player.last_name,
            photo_url: player.photo_url
          }
        });
      }

      if (url.pathname === "/city") {
        const player =
          await getOrCreatePlayer(
            telegramUser,
            env
          );

        const city =
          await getOrCreateCity(
            player.id,
            env
          );

        return json({
          success: true,

          city: {
            id: city.id,
            name: city.name,
            is_public: city.is_public
          }
        });
      }

      return json({
        success: false,
        error: "Route not found"
      }, 404);

    } catch (error) {
      console.error(
        "Worker error:",
        error
      );

      return json({
        success: false,

        error:
          error instanceof Error
            ? error.message
            : String(error)
      }, 500);
    }
  }
};


// ======================================================
// TELEGRAM AUTH
// ======================================================

async function validateTelegramInitData(
  initData,
  botToken
) {
  if (
    typeof initData !== "string" ||
    !initData ||
    typeof botToken !== "string" ||
    !botToken
  ) {
    return null;
  }

  const params =
    new URLSearchParams(initData);

  const receivedHash =
    params.get("hash");

  if (!receivedHash) {
    return null;
  }

  params.delete("hash");

  const dataCheckString =
    [...params.entries()]
      .sort(([a], [b]) =>
        a.localeCompare(b)
      )
      .map(([key, value]) =>
        `${key}=${value}`
      )
      .join("\n");

  try {
    const webAppDataKey =
      await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(
          "WebAppData"
        ),
        {
          name: "HMAC",
          hash: "SHA-256"
        },
        false,
        ["sign"]
      );

    const secretKey =
      await crypto.subtle.sign(
        "HMAC",
        webAppDataKey,
        new TextEncoder().encode(
          botToken
        )
      );

    const validationKey =
      await crypto.subtle.importKey(
        "raw",
        secretKey,
        {
          name: "HMAC",
          hash: "SHA-256"
        },
        false,
        ["sign"]
      );

    const calculatedHashBuffer =
      await crypto.subtle.sign(
        "HMAC",
        validationKey,
        new TextEncoder().encode(
          dataCheckString
        )
      );

    const calculatedHash =
      [...new Uint8Array(
        calculatedHashBuffer
      )]
        .map(byte =>
          byte.toString(16).padStart(2, "0")
        )
        .join("");

    if (
      !constantTimeEqual(
        calculatedHash,
        receivedHash
      )
    ) {
      return null;
    }

    const authDate =
      Number(params.get("auth_date"));

    if (
      !Number.isFinite(authDate) ||
      authDate <= 0
    ) {
      return null;
    }

    const currentTime =
      Math.floor(Date.now() / 1000);

    const dataAge =
      currentTime - authDate;

    if (
      dataAge < 0 ||
      dataAge > 86400
    ) {
      return null;
    }

    const userString =
      params.get("user");

    if (!userString) {
      return null;
    }

    const user =
      JSON.parse(userString);

    if (
      !user ||
      typeof user !== "object" ||
      !user.id
    ) {
      return null;
    }

    return user;

  } catch (error) {
    console.error(
      "Telegram validation error:",
      error
    );

    return null;
  }
}


// ======================================================
// PLAYER
// ======================================================

async function getOrCreatePlayer(
  user,
  env
) {
  const existing =
    await supabaseRequest(
      `/rest/v1/players?telegram_id=eq.${encodeURIComponent(
        user.id
      )}&select=*`,
      {
        method: "GET"
      },
      env
    );

  if (
    existing &&
    existing.length > 0
  ) {
    const player = existing[0];

    const updated =
      await supabaseRequest(
        `/rest/v1/players?id=eq.${encodeURIComponent(
          player.id
        )}`,
        {
          method: "PATCH",

          headers: {
            "Prefer":
              "return=representation"
          },

          body: JSON.stringify({
            username:
              user.username ?? null,

            first_name:
              user.first_name ?? null,

            last_name:
              user.last_name ?? null,

            photo_url:
              user.photo_url ?? null,

            updated_at:
              new Date().toISOString()
          })
        },
        env
      );

    return updated[0];
  }

  const created =
    await supabaseRequest(
      "/rest/v1/players",
      {
        method: "POST",

        headers: {
          "Prefer":
            "return=representation"
        },

        body: JSON.stringify({
          telegram_id: user.id,

          username:
            user.username ?? null,

          first_name:
            user.first_name ?? null,

          last_name:
            user.last_name ?? null,

          photo_url:
            user.photo_url ?? null
        })
      },
      env
    );

  return created[0];
}


// ======================================================
// CITY
// ======================================================

async function getOrCreateCity(
  playerId,
  env
) {
  const existing =
    await supabaseRequest(
      `/rest/v1/cities?owner_id=eq.${encodeURIComponent(
        playerId
      )}&select=*`,
      {
        method: "GET"
      },
      env
    );

  if (
    existing &&
    existing.length > 0
  ) {
    return existing[0];
  }

  const created =
    await supabaseRequest(
      "/rest/v1/cities",
      {
        method: "POST",

        headers: {
          "Prefer":
            "return=representation"
        },

        body: JSON.stringify({
          owner_id: playerId,
          name: "Новое поселение",
          is_public: true
        })
      },
      env
    );

  return created[0];
}


// ======================================================
// SUPABASE
// ======================================================

async function supabaseRequest(
  path,
  options,
  env
) {
  const response =
    await fetch(
      `${env.SUPABASE_URL}${path}`,
      {
        ...options,

        headers: {
          "Content-Type":
            "application/json",

          "apikey":
            env.SUPABASE_SECRET_KEY,

          "Authorization":
            `Bearer ${env.SUPABASE_SECRET_KEY}`,

          ...(options.headers || {})
        }
      }
    );

  if (!response.ok) {
    const errorText =
      await response.text();

    console.error(
      "Supabase error:",
      response.status,
      errorText
    );

    throw new Error(
      `Supabase request failed: ${response.status} ${errorText}`
    );
  }

  return response.json();
}


// ======================================================
// HELPERS
// ======================================================

function constantTimeEqual(
  a,
  b
) {
  if (
    typeof a !== "string" ||
    typeof b !== "string" ||
    a.length !== b.length
  ) {
    return false;
  }

  let result = 0;

  for (
    let i = 0;
    i < a.length;
    i++
  ) {
    result |=
      a.charCodeAt(i) ^
      b.charCodeAt(i);
  }

  return result === 0;
}


function json(
  data,
  status = 200
) {
  return new Response(
    JSON.stringify(data),
    {
      status,

      headers: {
        ...corsHeaders,

        "Content-Type":
          "application/json; charset=utf-8"
      }
    }
  );
}
