
import "dotenv/config";

import { randomBytes } from "node:crypto";
import Koa from "koa";
import Router from "@koa/router";
import mount from "koa-mount";
import { OAuth2Client } from "google-auth-library";
import * as oidc from "oidc-provider";

// --------------------------------------------------
// Environment
// --------------------------------------------------

function requiredEnv(name: string): string {
  const value = process.env[name];

  if (!value) {
    throw new Error(`Missing environment variable: ${name}`);
  }

  return value;
}

const port = Number(process.env.PORT ?? "3000");

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("Invalid PORT");
}

const env = {
  port,
  issuer: requiredEnv("ISSUER"),

  googleClientId: requiredEnv("GOOGLE_CLIENT_ID"),
  googleClientSecret: requiredEnv("GOOGLE_CLIENT_SECRET"),
  googleRedirectUri: requiredEnv("GOOGLE_REDIRECT_URI"),

  workspaceDomain: requiredEnv("WORKSPACE_DOMAIN"),

  oidcClientId: requiredEnv("OIDC_CLIENT_ID"),
  oidcClientSecret: requiredEnv("OIDC_CLIENT_SECRET"),

  sessionSecret: requiredEnv("SESSION_SECRET"),
};

// --------------------------------------------------
// Users
// --------------------------------------------------

interface User {
  id: string;
  email: string;
  name: string;
  picture?: string;
}

const users = new Map<string, User>();

// OAuth state -> OIDC interaction UID
const pendingStates = new Map<string, string>();

// --------------------------------------------------
// Google OAuth
// --------------------------------------------------

const google = new OAuth2Client(
  env.googleClientId,
  env.googleClientSecret,
  env.googleRedirectUri,
);

// --------------------------------------------------
// OIDC Provider
// --------------------------------------------------

const provider = new oidc.Provider(env.issuer, {
  clients: [
    {
      client_id: env.oidcClientId,
      client_secret: env.oidcClientSecret,
      redirect_uris: [
        "http://localhost:8080/callback",
      ],
      response_types: ["code"],
      grant_types: ["authorization_code"],
    },
  ],

  findAccount: async (_ctx, id) => {
    const user = users.get(id);

    if (!user) {
      return undefined;
    }

    return {
      accountId: user.id,

      async claims() {
        return {
          sub: user.id,
          email: user.email,
          email_verified: true,
          name: user.name,
          picture: user.picture,
        };
      },
    };
  },

  claims: {
    openid: ["sub"],
    email: ["email", "email_verified"],
    profile: ["name", "picture"],
  },

  interactions: {
    url(_ctx, interaction) {
      return `/interaction/${interaction.uid}`;
    },
  },
});

// --------------------------------------------------
// Koa Application
// --------------------------------------------------

const app = new Koa();
const router = new Router();

app.keys = [env.sessionSecret];

// --------------------------------------------------
// Interaction: Google Login
// --------------------------------------------------

router.get("/interaction/:uid", async (ctx) => {
  const state = randomBytes(32).toString("base64url");

  pendingStates.set(state, ctx.params.uid);

  ctx.cookies.set("google_oauth_state", state, {
    httpOnly: true,
    sameSite: "lax",
    secure: false, // localhost only
    signed: true,
    overwrite: true,
    maxAge: 10 * 60 * 1000,
  });

  const url = google.generateAuthUrl({
    scope: ["openid", "email", "profile"],
    state,
    hd: env.workspaceDomain,
    prompt: "select_account",
  });

  ctx.redirect(url);
});

// --------------------------------------------------
// Google Callback
// --------------------------------------------------

router.get("/google/callback", async (ctx) => {
  const { code, state, error } = ctx.query;

  if (error) {
    ctx.status = 401;
    ctx.body = "Google authentication was cancelled or failed";
    return;
  }

  if (
    typeof code !== "string" ||
    typeof state !== "string"
  ) {
    ctx.status = 400;
    ctx.body = "Invalid OAuth callback";
    return;
  }

  const cookieState = ctx.cookies.get(
    "google_oauth_state",
    { signed: true },
  );

  const interactionUid = pendingStates.get(state);

  if (
    !cookieState ||
    cookieState !== state ||
    !interactionUid
  ) {
    ctx.status = 400;
    ctx.body = "Invalid OAuth state";
    return;
  }

  // Consume state to prevent replay
  pendingStates.delete(state);

  ctx.cookies.set("google_oauth_state", "", {
    maxAge: 0,
    httpOnly: true,
    sameSite: "lax",
    signed: true,
  });

  try {
    const { tokens } = await google.getToken(code);

    if (!tokens.id_token) {
      ctx.status = 401;
      ctx.body = "Google ID Token not found";
      return;
    }

    // Verify Google ID Token
    const ticket = await google.verifyIdToken({
      idToken: tokens.id_token,
      audience: env.googleClientId,
    });

    const payload = ticket.getPayload();

    if (!payload?.sub || !payload.email) {
      ctx.status = 401;
      ctx.body = "Invalid Google account";
      return;
    }

    console.log("[Google Login] User information:", {
      sub: payload.sub,
      email: payload.email,
      email_verified: payload.email_verified,
      name: payload.name,
      given_name: payload.given_name,
      family_name: payload.family_name,
      picture: payload.picture,
      hd: payload.hd,
      locale: payload.locale,
    });

    // Workspace verification
    if (
      payload.hd?.toLowerCase() !==
      env.workspaceDomain.toLowerCase()
    ) {
      ctx.status = 403;
      ctx.body = "Workspace account required";
      return;
    }

    if (!payload.email_verified) {
      ctx.status = 403;
      ctx.body = "Email is not verified";
      return;
    }

    // Find or create user
    let user = users.get(payload.sub);

    if (!user) {
      user = {
        id: payload.sub,
        email: payload.email,
        name: payload.name ?? payload.email,
        picture: payload.picture,
      };

      users.set(user.id, user);
    }

    // Complete OIDC interaction
    await provider.interactionFinished(
      ctx.req,
      ctx.res,
      {
        login: {
          accountId: user.id,
        },
      },
      {
        mergeWithLastSubmission: false,
      },
    );

  } catch (err) {
    console.error("Google authentication error:", err);

    if (!ctx.headerSent) {
      ctx.status = 500;
      ctx.body = "Authentication failed";
    }
  }
});

// --------------------------------------------------
// Mount routes
// --------------------------------------------------

// Custom routes must be registered before oidc-provider.
app.use(router.routes());
app.use(router.allowedMethods());

// Mount OIDC Provider
app.use(mount(provider));

// --------------------------------------------------
// Start
// --------------------------------------------------

app.listen(env.port, () => {
  console.log(`OIDC Provider: ${env.issuer}`);
});
