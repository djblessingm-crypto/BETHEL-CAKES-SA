
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const nodemailer = require("nodemailer");

const ROOT = __dirname;

const CONFIG_FILE = path.join(ROOT, "config.json");
const USERS_FILE = path.join(ROOT, "users.json");
const REVIEWS_FILE = path.join(ROOT, "reviews.json");

if (!fs.existsSync(CONFIG_FILE)) {
    console.error("ERROR: config.json is missing.");
    console.error("Create config.json before starting the server.");
    process.exit(1);
}

const CONFIG = JSON.parse(
    fs.readFileSync(CONFIG_FILE, "utf8")
);

const PORT = CONFIG.port || 3000;
const HOST = "127.0.0.1";

const sessions = new Map();
const verificationCodes = new Map();


// ==============================
// FILE FUNCTIONS
// ==============================

function readJson(file, fallback) {
    try {
        return JSON.parse(
            fs.readFileSync(file, "utf8")
        );
    } catch {
        return fallback;
    }
}

function writeJson(file, data) {
    fs.writeFileSync(
        file,
        JSON.stringify(data, null, 2),
        "utf8"
    );
}


// ==============================
// RESPONSE FUNCTIONS
// ==============================

function json(res, status, data) {
    res.writeHead(status, {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store"
    });

    res.end(JSON.stringify(data));
}


// ==============================
// REQUEST BODY
// ==============================

function getBody(req) {
    return new Promise((resolve, reject) => {

        let raw = "";

        req.on("data", chunk => {

            raw += chunk;

            if (raw.length > 1000000) {
                req.destroy();
                reject(
                    new Error("Request body too large.")
                );
            }

        });

        req.on("end", () => {

            if (!raw) {
                resolve({});
                return;
            }

            try {
                resolve(JSON.parse(raw));
            } catch {
                reject(
                    new Error("Invalid JSON.")
                );
            }

        });

        req.on("error", reject);

    });
}


// ==============================
// PASSWORD SECURITY
// ==============================

function hashPassword(
    password,
    salt = crypto.randomBytes(16).toString("hex")
) {

    const hash = crypto
        .scryptSync(password, salt, 64)
        .toString("hex");

    return {
        salt,
        hash
    };
}


function checkPassword(password, user) {

    const hash = crypto
        .scryptSync(password, user.salt, 64)
        .toString("hex");

    const stored = Buffer.from(
        user.passwordHash,
        "hex"
    );

    const supplied = Buffer.from(
        hash,
        "hex"
    );

    if (stored.length !== supplied.length) {
        return false;
    }

    return crypto.timingSafeEqual(
        stored,
        supplied
    );
}


// ==============================
// TOKENS
// ==============================

function createToken() {
    return crypto
        .randomBytes(32)
        .toString("hex");
}


function getCookieToken(req) {

    const cookies = req.headers.cookie || "";

    const match = cookies.match(
        /(?:^|;\s*)bethel_session=([^;]+)/
    );

    if (!match) {
        return null;
    }

    return decodeURIComponent(match[1]);
}


// ==============================
// SESSION
// ==============================

function setSession(res, token) {

    res.setHeader(
        "Set-Cookie",
        `bethel_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800`
    );
}


function clearSession(res) {

    res.setHeader(
        "Set-Cookie",
        "bethel_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"
    );
}


function getCurrentUser(req) {

    const sessionToken =
        getCookieToken(req);

    if (!sessionToken) {
        return null;
    }

    const session =
        sessions.get(sessionToken);

    if (!session) {
        return null;
    }

    if (Date.now() > session.expires) {

        sessions.delete(sessionToken);

        return null;
    }

    const users =
        readJson(USERS_FILE, []);

    return users.find(
        user => user.id === session.userId
    ) || null;
}


// ==============================
// SAFE USER DATA
// ==============================

function safeUser(user) {

    return {
        id: user.id,
        name: user.name,
        email: user.email,
        verified: user.verified
    };
}


// ==============================
// TEXT CLEANING
// ==============================

function cleanText(value, maxLength) {

    return String(value || "")
        .trim()
        .slice(0, maxLength);
}


// ==============================
// HTML ESCAPING
// ==============================

function escapeHtml(value) {

    return String(value).replace(
        /[&<>"']/g,
        character => {

            const characters = {
                "&": "&amp;",
                "<": "&lt;",
                ">": "&gt;",
                '"': "&quot;",
                "'": "&#39;"
            };

            return characters[character];
        }
    );
}


// ==============================
// EMAIL
// ==============================

function createTransporter() {

    const smtp = CONFIG.smtp;

    return nodemailer.createTransport({
        host: smtp.host,
        port: smtp.port,
        secure: !!smtp.secure,

        auth: {
            user: smtp.user,
            pass: smtp.pass
        }
    });
}


async function sendVerificationEmail(
    email,
    name,
    code
) {

    const transporter =
        createTransporter();

    await transporter.sendMail({

        from: CONFIG.smtp.from,

        to: email,

        subject:
            "Bethel Cakes Email Verification",

        text:
            `Hello ${name},

Your Bethel Cakes verification code is:

${code}

This code expires in 10 minutes.

Bethel Cakes
Every Cake Tells a Story`,

        html:
            `
            <div style="
                font-family:Arial,sans-serif;
                max-width:560px;
                margin:auto;
                padding:30px;
                background:#fffaf5;
                border-radius:24px;
            ">

                <h1 style="
                    color:#6d1025;
                ">
                    Bethel Cakes
                </h1>

                <p>
                    Hello ${escapeHtml(name)},
                </p>

                <p>
                    Your email verification code is:
                </p>

                <div style="
                    font-size:34px;
                    font-weight:bold;
                    letter-spacing:8px;
                    color:#6d1025;
                    background:#f4e8df;
                    padding:20px;
                    border-radius:18px;
                    text-align:center;
                ">
                    ${code}
                </div>

                <p>
                    This code expires in 10 minutes.
                </p>

                <p>
                    Every Cake Tells a Story
                </p>

            </div>
            `
    });
}


// ==============================
// STATIC FILE SERVER
// ==============================

function serveStaticFile(res, pathname) {

    let requestedFile =
        pathname === "/"
            ? "/index.html"
            : pathname;

    const normalized =
        path.normalize(requestedFile);

    const cleanPath =
        normalized.replace(
            /^(\.\.[/\\])+/, ""
        );

    const fullPath =
        path.join(ROOT, cleanPath);

    if (!fullPath.startsWith(ROOT)) {
        return false;
    }

    if (!fs.existsSync(fullPath)) {
        return false;
    }

    if (
        fs.statSync(fullPath).isDirectory()
    ) {
        return false;
    }

    const extension =
        path.extname(fullPath)
            .toLowerCase();

    const contentTypes = {

        ".html": "text/html",

        ".css": "text/css",

        ".js": "text/javascript",

        ".json": "application/json",

        ".png": "image/png",

        ".jpg": "image/jpeg",

        ".jpeg": "image/jpeg",

        ".webp": "image/webp",

        ".svg": "image/svg+xml",

        ".ico": "image/x-icon"

    };

    const contentType =
        contentTypes[extension]
        || "application/octet-stream";

    res.writeHead(200, {
        "Content-Type":
            contentType +
            (contentType.startsWith("text/")
                ? "; charset=utf-8"
                : "")
    });

    fs.createReadStream(
        fullPath
    ).pipe(res);

    return true;
}


// ==============================
// SERVER
// ==============================

const server =
    http.createServer(
        async (req, res) => {

            const url =
                new URL(
                    req.url,
                    `http://${req.headers.host || HOST}`
                );

            const pathname =
                url.pathname;


            try {

                // ==========================
                // SIGN UP
                // ==========================

                if (
                    pathname === "/api/signup" &&
                    req.method === "POST"
                ) {

                    const data =
                        await getBody(req);

                    const name =
                        cleanText(
                            data.name,
                            80
                        );

                    const email =
                        cleanText(
                            data.email,
                            160
                        ).toLowerCase();

                    const password =
                        String(
                            data.password || ""
                        );

                    const confirmPassword =
                        String(
                            data.confirmPassword || ""
                        );


                    if (
                        !name ||
                        !email ||
                        !email.includes("@")
                    ) {

                        return json(
                            res,
                            400,
                            {
                                error:
                                    "Enter a valid name and email."
                            }
                        );
                    }


                    if (
                        password.length < 8
                    ) {

                        return json(
                            res,
                            400,
                            {
                                error:
                                    "Password must be at least 8 characters."
                            }
                        );
                    }


                    if (
                        password !== confirmPassword
                    ) {

                        return json(
                            res,
                            400,
                            {
                                error:
                                    "Passwords do not match."
                            }
                        );
                    }


                    const users =
                        readJson(
                            USERS_FILE,
                            []
                        );


                    const existingUser =
                        users.find(
                            user =>
                                user.email === email
                        );


                    if (existingUser) {

                        return json(
                            res,
                            409,
                            {
                                error:
                                    "An account with that email already exists."
                            }
                        );
                    }


                    const passwordData =
                        hashPassword(password);


                    const user = {

                        id:
                            crypto.randomUUID(),

                        name,

                        email,

                        salt:
                            passwordData.salt,

                        passwordHash:
                            passwordData.hash,

                        verified:
                            false,

                        createdAt:
                            new Date().toISOString()

                    };


                    users.push(user);

                    writeJson(
                        USERS_FILE,
                        users
                    );


                    const code =
                        String(
                            crypto.randomInt(
                                100000,
                                1000000
                            )
                        );


                    verificationCodes.set(
                        email,
                        {
                            code,

                            expires:
                                Date.now()
                                +
                                10 * 60 * 1000
                        }
                    );


                    try {

                        await sendVerificationEmail(
                            email,
                            name,
                            code
                        );

                    } catch (error) {

                        console.error(
                            "EMAIL ERROR:",
                            error
                        );

                        return json(
                            res,
                            500,
                            {
                                error:
                                    "Account created, but the verification email could not be sent. Check your config.json SMTP settings."
                            }
                        );
                    }


                    return json(
                        res,
                        201,
                        {
                            ok: true,

                            message:
                                "Account created. Check your email for the verification code.",

                            email
                        }
                    );
                }


                // ==========================
                // VERIFY EMAIL
                // ==========================

                if (
                    pathname === "/api/verify" &&
                    req.method === "POST"
                ) {

                    const data =
                        await getBody(req);

                    const email =
                        cleanText(
                            data.email,
                            160
                        ).toLowerCase();

                    const code =
                        cleanText(
                            data.code,
                            6
                        );


                    const verification =
                        verificationCodes.get(
                            email
                        );


                    if (
                        !verification ||
                        Date.now() >
                            verification.expires ||
                        verification.code !== code
                    ) {

                        return json(
                            res,
                            400,
                            {
                                error:
                                    "Invalid or expired verification code."
                            }
                        );
                    }


                    const users =
                        readJson(
                            USERS_FILE,
                            []
                        );


                    const user =
                        users.find(
                            item =>
                                item.email === email
                        );


                    if (!user) {

                        return json(
                            res,
                            404,
                            {
                                error:
                                    "Account not found."
                            }
                        );
                    }


                    user.verified = true;

                    writeJson(
                        USERS_FILE,
                        users
                    );


                    verificationCodes.delete(
                        email
                    );


                    return json(
                        res,
                        200,
                        {
                            ok: true,

                            message:
                                "Email verified. You can now log in."
                        }
                    );
                }


                // ==========================
                // RESEND VERIFICATION CODE
                // ==========================

                if (
                    pathname === "/api/resend-code" &&
                    req.method === "POST"
                ) {

                    const data =
                        await getBody(req);

                    const email =
                        cleanText(
                            data.email,
                            160
                        ).toLowerCase();


                    const users =
                        readJson(
                            USERS_FILE,
                            []
                        );


                    const user =
                        users.find(
                            item =>
                                item.email === email
                        );


                    if (!user) {

                        return json(
                            res,
                            404,
                            {
                                error:
                                    "Account not found."
                            }
                        );
                    }


                    if (user.verified) {

                        return json(
                            res,
                            400,
                            {
                                error:
                                    "This email is already verified."
                            }
                        );
                    }


                    const code =
                        String(
                            crypto.randomInt(
                                100000,
                                1000000
                            )
                        );


                    verificationCodes.set(
                        email,
                        {
                            code,

                            expires:
                                Date.now()
                                +
                                10 * 60 * 1000
                        }
                    );


                    try {

                        await sendVerificationEmail(
                            email,
                            user.name,
                            code
                        );


                        return json(
                            res,
                            200,
                            {
                                ok: true,

                                message:
                                    "A new verification code was sent."
                            }
                        );

                    } catch (error) {

                        console.error(
                            "EMAIL ERROR:",
                            error
                        );

                        return json(
                            res,
                            500,
                            {
                                error:
                                    "Could not send the email. Check your config.json SMTP settings."
                            }
                        );
                    }
                }


                // ==========================
                // LOGIN
                // ==========================

                if (
                    pathname === "/api/login" &&
                    req.method === "POST"
                ) {

                    const data =
                        await getBody(req);

                    const email =
                        cleanText(
                            data.email,
                            160
                        ).toLowerCase();

                    const password =
                        String(
                            data.password || ""
                        );


                    const users =
                        readJson(
                            USERS_FILE,
                            []
                        );


                    const user =
                        users.find(
                            item =>
                                item.email === email
                        );


                    if (
                        !user ||
                        !checkPassword(
                            password,
                            user
                        )
                    ) {

                        return json(
                            res,
                            401,
                            {
                                error:
                                    "Incorrect email or password."
                            }
                        );
                    }


                    if (!user.verified) {

                        return json(
                            res,
                            403,
                            {
                                error:
                                    "Please verify your email before logging in."
                            }
                        );
                    }


                    const sessionToken =
                        createToken();


                    sessions.set(
                        sessionToken,
                        {
                            userId:
                                user.id,

                            expires:
                                Date.now()
                                +
                                7 *
                                24 *
                                60 *
                                60 *
                                1000
                        }
                    );


                    setSession(
                        res,
                        sessionToken
                    );


                    return json(
                        res,
                        200,
                        {
                            ok: true,

                            user:
                                safeUser(user)
                        }
                    );
                }


                // ==========================
                // LOGOUT
                // ==========================

                if (
                    pathname === "/api/logout" &&
                    req.method === "POST"
                ) {

                    const token =
                        getCookieToken(req);


                    if (token) {
                        sessions.delete(token);
                    }


                    clearSession(res);


                    return json(
                        res,
                        200,
                        {
                            ok: true
                        }
                    );
                }


                // ==========================
                // CURRENT USER
                // ==========================

                if (
                    pathname === "/api/me" &&
                    req.method === "GET"
                ) {

                    const user =
                        getCurrentUser(req);


                    return json(
                        res,
                        200,
                        {
                            loggedIn:
                                !!user,

                            user:
                                user
                                    ? safeUser(user)
                                    : null
                        }
                    );
                }


                // ==========================
                // APPROVED REVIEWS
                // ==========================

                if (
                    pathname === "/api/reviews" &&
                    req.method === "GET"
                ) {

                    const reviews =
                        readJson(
                            REVIEWS_FILE,
                            []
                        );


                    const approved =
                        reviews
                            .filter(
                                review =>
                                    review.status ===
                                    "approved"
                            )
                            .sort(
                                (a, b) =>
                                    new Date(
                                        b.createdAt
                                    ) -
                                    new Date(
                                        a.createdAt
                                    )
                            );


                    return json(
                        res,
                        200,
                        {
                            reviews:
                                approved
                        }
                    );
                }


                // ==========================
                // CREATE REVIEW
                // ==========================

                if (
                    pathname === "/api/reviews" &&
                    req.method === "POST"
                ) {

                    const user =
                        getCurrentUser(req);


                    if (!user) {

                        return json(
                            res,
                            401,
                            {
                                error:
                                    "Please log in to submit a review."
                            }
                        );
                    }


                    const data =
                        await getBody(req);


                    const rating =
                        Number(data.rating);


                    const text =
                        cleanText(
                            data.text,
                            1200
                        );


                    if (
                        !Number.isInteger(rating) ||
                        rating < 1 ||
                        rating > 5
                    ) {

                        return json(
                            res,
                            400,
                            {
                                error:
                                    "Choose a rating from 1 to 5."
                            }
                        );
                    }


                    if (text.length < 5) {

                        return json(
                            res,
                            400,
                            {
                                error:
                                    "Write a little more about your experience."
                            }
                        );
                    }


                    const reviews =
                        readJson(
                            REVIEWS_FILE,
                            []
                        );


                    const existing =
                        reviews.find(
                            review =>
                                review.userId ===
                                user.id
                        );


                    if (existing) {

                        return json(
                            res,
                            409,
                            {
                                error:
                                    "You already have a review. You can edit it from your account."
                            }
                        );
                    }


                    const now =
                        new Date().toISOString();


                    reviews.push({

                        id:
                            crypto.randomUUID(),

                        userId:
                            user.id,

                        name:
                            user.name,

                        rating,

                        text,

                        status:
                            "pending",

                        createdAt:
                            now,

                        updatedAt:
                            now

                    });


                    writeJson(
                        REVIEWS_FILE,
                        reviews
                    );


                    return json(
                        res,
                        201,
                        {
                            ok: true,

                            message:
                                "Thank you. Your review is waiting for approval."
                        }
                    );
                }


                // ==========================
                // MY REVIEW
                // ==========================

                if (
                    pathname === "/api/my-review" &&
                    req.method === "GET"
                ) {

                    const user =
                        getCurrentUser(req);


                    if (!user) {

                        return json(
                            res,
                            401,
                            {
                                error:
                                    "Not logged in."
                            }
                        );
                    }


                    const reviews =
                        readJson(
                            REVIEWS_FILE,
                            []
                        );


                    const review =
                        reviews.find(
                            item =>
                                item.userId ===
                                user.id
                        ) || null;


                    return json(
                        res,
                        200,
                        {
                            review
                        }
                    );
                }


                // ==========================
                // EDIT MY REVIEW
                // ==========================

                if (
                    pathname === "/api/my-review" &&
                    req.method === "PUT"
                ) {

                    const user =
                        getCurrentUser(req);


                    if (!user) {

                        return json(
                            res,
                            401,
                            {
                                error:
                                    "Not logged in."
                            }
                        );
                    }


                    const data =
                        await getBody(req);


                    const rating =
                        Number(data.rating);


                    const text =
                        cleanText(
                            data.text,
                            1200
                        );


                    if (
                        !Number.isInteger(rating) ||
                        rating < 1 ||
                        rating > 5 ||
                        text.length < 5
                    ) {

                        return json(
                            res,
                            400,
                            {
                                error:
                                    "Enter a 1–5 star rating and a review."
                            }
                        );
                    }


                    const reviews =
                        readJson(
                            REVIEWS_FILE,
                            []
                        );


                    const review =
                        reviews.find(
                            item =>
                                item.userId ===
                                user.id
                        );


                    if (!review) {

                        return json(
                            res,
                            404,
                            {
                                error:
                                    "Review not found."
                            }
                        );
                    }


                    review.rating =
                        rating;

                    review.text =
                        text;

                    review.status =
                        "pending";

                    review.updatedAt =
                        new Date().toISOString();


                    writeJson(
                        REVIEWS_FILE,
                        reviews
                    );


                    return json(
                        res,
                        200,
                        {
                            ok: true,

                            message:
                                "Review updated and sent for approval again."
                        }
                    );
                }


                // ==========================
                // DELETE MY REVIEW
                // ==========================

                if (
                    pathname === "/api/my-review" &&
                    req.method === "DELETE"
                ) {

                    const user =
                        getCurrentUser(req);


                    if (!user) {

                        return json(
                            res,
                            401,
                            {
                                error:
                                    "Not logged in."
                            }
                        );
                    }


                    const reviews =
                        readJson(
                            REVIEWS_FILE,
                            []
                        );


                    const remaining =
                        reviews.filter(
                            review =>
                                review.userId !==
                                user.id
                        );


                    writeJson(
                        REVIEWS_FILE,
                        remaining
                    );


                    return json(
                        res,
                        200,
                        {
                            ok: true
                        }
                    );
                }


                // ==========================
                // ADMIN: GET REVIEWS
                // ==========================

                if (
                    pathname === "/api/admin/reviews" &&
                    req.method === "GET"
                ) {

                    if (
                        req.headers["x-admin-key"] !==
                        CONFIG.adminKey
                    ) {

                        return json(
                            res,
                            401,
                            {
                                error:
                                    "Unauthorized."
                            }
                        );
                    }


                    const reviews =
                        readJson(
                            REVIEWS_FILE,
                            []
                        );


                    reviews.sort(
                        (a, b) =>
                            new Date(
                                b.createdAt
                            ) -
                            new Date(
                                a.createdAt
                            )
                    );


                    return json(
                        res,
                        200,
                        {
                            reviews
                        }
                    );
                }


                // ==========================
                // ADMIN: UPDATE REVIEW
                // ==========================

                if (
                    pathname.startsWith(
                        "/api/admin/reviews/"
                    ) &&
                    req.method === "PATCH"
                ) {

                    if (
                        req.headers["x-admin-key"] !==
                        CONFIG.adminKey
                    ) {

                        return json(
                            res,
                            401,
                            {
                                error:
                                    "Unauthorized."
                            }
                        );
                    }


                    const reviewId =
                        pathname.split("/").pop();


                    const data =
                        await getBody(req);


                    const reviews =
                        readJson(
                            REVIEWS_FILE,
                            []
                        );


                    const review =
                        reviews.find(
                            item =>
                                item.id ===
                                reviewId
                        );


                    if (!review) {

                        return json(
                            res,
                            404,
                            {
                                error:
                                    "Review not found."
                            }
                        );
                    }


                    const validStatuses = [
                        "approved",
                        "pending",
                        "deleted"
                    ];


                    if (
                        !validStatuses.includes(
                            data.status
                        )
                    ) {

                        return json(
                            res,
                            400,
                            {
                                error:
                                    "Invalid review status."
                            }
                        );
                    }


                    if (
                        data.status ===
                        "deleted"
                    ) {

                        const remaining =
                            reviews.filter(
                                item =>
                                    item.id !==
                                    reviewId
                            );


                        writeJson(
                            REVIEWS_FILE,
                            remaining
                        );

                    } else {

                        review.status =
                            data.status;


                        writeJson(
                            REVIEWS_FILE,
                            reviews
                        );
                    }


                    return json(
                        res,
                        200,
                        {
                            ok: true
                        }
                    );
                }


                // ==========================
                // STATIC WEBSITE
                // ==========================

                if (
                    req.method === "GET" &&
                    serveStaticFile(
                        res,
                        pathname
                    )
                ) {
                    return;
                }


                // ==========================
                // NOT FOUND
                // ==========================

                res.writeHead(
                    404,
                    {
                        "Content-Type":
                            "text/plain; charset=utf-8"
                    }
                );

                res.end(
                    "Page not found."
                );


            } catch (error) {

                console.error(
                    "SERVER ERROR:",
                    error
                );


                json(
                    res,
                    500,
                    {
                        error:
                            "Server error."
                    }
                );
            }

        }
    );


// ==============================
// START SERVER
// ==============================

server.listen(
    PORT,
    HOST,
    () => {

        console.log(
            `Bethel Cakes running at http://${HOST}:${PORT}`
        );

    }
);

