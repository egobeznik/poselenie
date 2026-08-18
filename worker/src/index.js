export default {
    async fetch(request) {
        return new Response(
            JSON.stringify({
                success: true,
                service: "poselenie-api",
                status: "online"
            }),
            {
                headers: {
                    "Content-Type": "application/json; charset=utf-8"
                }
            }
        );
    }
};

// Poselenie API v0.1
