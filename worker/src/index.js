const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
};

export default {
    async fetch(request, env) {

        // CORS preflight
        if (request.method === "OPTIONS") {
            return new Response(null, {
                headers: corsHeaders
            });
        }

        // Health check
        if (request.method === "GET") {
            return json({
                success: true,
                service: "poselenie-api",
                status: "online"
            });
        }

        // Только POST
        if (request.method !== "POST") {
            return json(
                {
                    success: false,
                    error: "Method not allowed"
                },
                405
            );
        }

        try {
            const body = await request.json();

            if (!body.initData) {
                return json(
                    {
                        success: false,
                        error: "Telegram initData is required"
                    },
                    400
                );
            }

            // Проверяем Telegram initData
            const telegramUser = await validateTelegramInitData(
                body.initData,
                env.TELEGRAM_BOT_TOKEN
            );

            if (!telegramUser) {
                return json(
                    {
                        success: false,
                        error: "Invalid Telegram authentication"
                    },
                    401
                );
            }

            // Находим или создаём игрока
            const player = await getOrCreatePlayer(
                telegramUser,
                env
            );

            // Находим или создаём город
            const city = await getOrCreateCity(
                player.id,
                env
            );

            // Возвращаем данные Mini App
            return json({
                success: true,

                player: {
                    id: player.id,
                    telegram_id: player.telegram_id,
                    username: player.username,
                    first_name: player.first_name,
                    last_name: player.last_name,
                    photo_url: player.photo_url
                },

                city: {
                    id: city.id,
                    name: city.name,
                    is_public: city.is_public
                }
            });

        } catch (error) {

            console.error("Worker error:", error);

            return json(
                {
                    success: false,
                    error: "Internal server error"
                },
                500
            );
        }
    }
};


/*
==================================================
TELEGRAM AUTHENTICATION
==================================================
*/

async function validateTelegramInitData(
    initData,
    botToken
) {

    const params = new URLSearchParams(initData);

    const receivedHash = params.get("hash");

    if (!receivedHash) {
        return null;
    }

    // Удаляем hash из строки проверки
    params.delete("hash");

    // Формируем data-check-string
    const dataCheckString = [...params.entries()]
        .sort(([keyA], [keyB]) =>
            keyA.localeCompare(keyB)
        )
        .map(([key, value]) =>
            `${key}=${value}`
        )
        .join("\n");


    /*
    --------------------------------------------------
    Первый HMAC

    secret_key =
    HMAC-SHA256(
        key = bot_token,
        data = "WebAppData"
    )
    --------------------------------------------------
    */

    const botTokenKey =
        await crypto.subtle.importKey(
            "raw",
            new TextEncoder().encode(botToken),
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
            botTokenKey,
            new TextEncoder().encode("WebAppData")
        );


    /*
    --------------------------------------------------
    Второй HMAC

    calculated_hash =
    HMAC-SHA256(
        key = secret_key,
        data = data_check_string
    )
    --------------------------------------------------
    */

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
            byte
                .toString(16)
                .padStart(2, "0")
        )
        .join("");


    // Сравниваем хэши
    if (
        !constantTimeEqual(
            calculatedHash,
            receivedHash
        )
    ) {
        return null;
    }


    /*
    --------------------------------------------------
    Проверяем auth_date
    --------------------------------------------------
    */

    const authDate =
        Number(params.get("auth_date"));

    if (!authDate) {
        return null;
    }


    const currentTime =
        Math.floor(
            Date.now() / 1000
        );


    const dataAge =
        currentTime - authDate;


    // Не принимаем данные старше 24 часов
    if (
        dataAge < 0 ||
        dataAge > 86400
    ) {
        return null;
    }


    /*
    --------------------------------------------------
    Получаем пользователя Telegram
    --------------------------------------------------
    */

    const userString =
        params.get("user");

    if (!userString) {
        return null;
    }


    try {

        return JSON.parse(
            userString
        );

    } catch {

        return null;
    }
}


/*
==================================================
PLAYERS
==================================================
*/

async function getOrCreatePlayer(
    user,
    env
) {

    // Ищем игрока по Telegram ID
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


    // Игрок уже существует
    if (existing.length > 0) {

        const player =
            existing[0];


        // Обновляем актуальные данные Telegram
        const updated =
            await supabaseRequest(
                `/rest/v1/players?id=eq.${player.id}`,
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


    // Создаём нового игрока
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

                    telegram_id:
                        user.id,

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


/*
==================================================
CITIES
==================================================
*/

async function getOrCreateCity(
    playerId,
    env
) {

    // Ищем существующий город
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


    // Город уже существует
    if (existing.length > 0) {
        return existing[0];
    }


    // Создаём новый город
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

                    owner_id:
                        playerId,

                    name:
                        "Новое поселение",

                    is_public:
                        true
                })
            },
            env
        );


    return created[0];
}


/*
==================================================
SUPABASE
==================================================
*/

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
            "Supabase request failed"
        );
    }


    return response.json();
}


/*
==================================================
HELPERS
==================================================
*/

function constantTimeEqual(
    a,
    b
) {

    if (a.length !== b.length) {
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
