// Local stand-in for the ID.me OAuth 2.0 endpoints used by this sample, for demos without ID.me credentials.
// Run: node mock_idme.js (port 3001, override with MOCK_IDME_PORT), then open
// http://localhost:3000/?idme_base_url=http://localhost:3001
const http = require("http");
const crypto = require("crypto");

const PORT = parseInt(process.env.MOCK_IDME_PORT || "3001", 10);
const TOKEN_TTL_SECONDS = 300;

const SUBGROUPS = {
  military: "Veteran",
  student: "Student",
  responder: "EMT",
  teacher: "Teacher"
};

const CODES = new Map();
const TOKENS = new Map();

const randomHex = (bytes) => crypto.randomBytes(bytes).toString("hex");

const escapeHtml = (text) => String(text == null ? "" : text).replace(/[&<>"']/g, (c) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
}[c]));

function send(res, status, headers, body) {
  res.writeHead(status, Object.assign({ "Access-Control-Allow-Origin": "*" }, headers));
  res.end(body);
}

function sendJson(res, status, payload) {
  send(res, status, { "Content-Type": "application/json" }, JSON.stringify(payload));
}

function oauthError(res, status, error, description) {
  sendJson(res, status, { error: error, error_description: description });
}

function isHttpUrl(value) {
  try {
    return ["http:", "https:"].includes(new URL(value).protocol);
  } catch (e) {
    return false;
  }
}

// token responses go in the URL fragment, code responses in the query string
function redirectWith(res, redirectUri, responseType, params) {
  const url = new URL(redirectUri);
  url.hash = "";
  const entries = Object.entries(params).filter(([, value]) => value);

  if (responseType === "token") {
    url.hash = new URLSearchParams(entries).toString();
  } else {
    entries.forEach(([key, value]) => url.searchParams.append(key, value));
  }
  send(res, 302, { Location: url.toString() }, "");
}

function readBody(req) {
  return new Promise((resolve) => {
    let body = "";
    req.on("data", (chunk) => { body += chunk; });
    req.on("end", () => resolve(new URLSearchParams(body)));
  });
}

function scopesFrom(params) {
  return (params.get("scope") || params.get("scopes") || "").split(/[ ,]+/).filter(Boolean);
}

function renderAuthorize(res, params) {
  const clientId = params.get("client_id");
  const redirectUri = params.get("redirect_uri");
  const responseType = params.get("response_type");

  if (!clientId || !redirectUri) return send(res, 400, { "Content-Type": "text/plain" }, "Missing client_id or redirect_uri");
  if (!isHttpUrl(redirectUri)) return send(res, 400, { "Content-Type": "text/plain" }, "redirect_uri must be an http(s) URL");
  if (!["token", "code"].includes(responseType)) return send(res, 400, { "Content-Type": "text/plain" }, "Unsupported response_type");

  const scope = scopesFrom(params).join(",");
  const hidden = { client_id: clientId, redirect_uri: redirectUri, response_type: responseType, scope: scope, state: params.get("state") || "" };
  const hiddenInputs = Object.entries(hidden)
    .map(([name, value]) => `<input type="hidden" name="${name}" value="${escapeHtml(value)}">`)
    .join("\n        ");

  send(res, 200, { "Content-Type": "text/html; charset=utf-8" }, `<html>
  <head><title>ID.me (mock) - Sign in</title></head>
  <body style="font-family: sans-serif; max-width: 420px; margin: 40px auto;">
    <h2>ID.me (mock)</h2>
    <p><strong>${escapeHtml(clientId)}</strong> is requesting your <strong>${escapeHtml(scope)}</strong> verification status.</p>
    <form method="post" action="/oauth/authorize">
        ${hiddenInputs}
      <p><label>First name <input name="fname" value="Jane"></label></p>
      <p><label>Last name <input name="lname" value="Doe"></label></p>
      <p><label>Email <input name="email" value="jane.doe@example.com"></label></p>
      <button type="submit" name="decision" value="allow">Allow</button>
      <button type="submit" name="decision" value="deny">Deny</button>
    </form>
  </body>
</html>`);
}

function issueToken(grant) {
  const accessToken = randomHex(24);
  TOKENS.set(accessToken, Object.assign({ expiresAt: Date.now() + TOKEN_TTL_SECONDS * 1000 }, grant));
  return accessToken;
}

async function handleAuthorizeDecision(req, res) {
  const params = await readBody(req);
  const redirectUri = params.get("redirect_uri");
  const responseType = params.get("response_type");
  const state = params.get("state");

  if (!isHttpUrl(redirectUri) || !["token", "code"].includes(responseType)) return oauthError(res, 400, "invalid_request", "Invalid redirect_uri or response_type");
  if (params.get("decision") !== "allow") return redirectWith(res, redirectUri, responseType, { error: "access_denied", state: state });

  const grant = {
    clientId: params.get("client_id"),
    redirectUri: redirectUri,
    scope: params.get("scope") || "",
    user: { uuid: randomHex(16), fname: params.get("fname"), lname: params.get("lname"), email: params.get("email") }
  };

  if (responseType === "token") {
    return redirectWith(res, redirectUri, "token", {
      access_token: issueToken(grant), token_type: "bearer", expires_in: String(TOKEN_TTL_SECONDS), scope: grant.scope, state: state
    });
  }

  const code = randomHex(16);
  CODES.set(code, grant);
  redirectWith(res, redirectUri, "code", { code: code, state: state });
}

async function handleToken(req, res) {
  const params = await readBody(req);
  let clientId = params.get("client_id");
  const basic = (req.headers.authorization || "").match(/^Basic (.+)$/i);
  if (basic) clientId = Buffer.from(basic[1], "base64").toString().split(":")[0];

  if (params.get("grant_type") !== "authorization_code") return oauthError(res, 400, "unsupported_grant_type", "Only authorization_code is supported");

  const code = params.get("code") || "";
  const grant = CODES.get(code);
  CODES.delete(code);
  if (!grant) return oauthError(res, 400, "invalid_grant", "Unknown or already used code");
  if (grant.clientId !== clientId) return oauthError(res, 401, "invalid_client", "client_id does not match the code");
  if (grant.redirectUri !== params.get("redirect_uri")) return oauthError(res, 400, "invalid_grant", "redirect_uri does not match");

  sendJson(res, 200, {
    access_token: issueToken(grant), token_type: "bearer", expires_in: TOKEN_TTL_SECONDS, refresh_token: randomHex(24), scope: grant.scope
  });
}

function handleAttributes(req, res, query) {
  const bearer = (req.headers.authorization || "").match(/^Bearer (.+)$/i);
  const token = bearer ? bearer[1] : query.get("access_token");
  const grant = TOKENS.get(token || "");

  if (!grant || grant.expiresAt < Date.now()) return oauthError(res, 401, "invalid_token", "Missing or invalid access token");

  const user = grant.user;
  sendJson(res, 200, {
    attributes: [
      { handle: "fname", name: "First Name", value: user.fname },
      { handle: "lname", name: "Last Name", value: user.lname },
      { handle: "email", name: "Email", value: user.email },
      { handle: "uuid", name: "Unique Identifier", value: user.uuid }
    ],
    status: scopesFrom(new URLSearchParams({ scope: grant.scope })).map((group) => ({
      group: group,
      subgroups: [SUBGROUPS[group] || group.charAt(0).toUpperCase() + group.slice(1)],
      verified: true
    }))
  });
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const route = `${req.method} ${url.pathname}`;

  if (req.method === "OPTIONS") {
    return send(res, 204, { "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Authorization, Content-Type" }, "");
  }

  switch (route) {
    case "GET /oauth/authorize": return renderAuthorize(res, url.searchParams);
    case "POST /oauth/authorize": return handleAuthorizeDecision(req, res);
    case "POST /oauth/token": return handleToken(req, res);
    case "GET /api/public/v3/attributes.json": return handleAttributes(req, res, url.searchParams);
    default: return send(res, 404, { "Content-Type": "text/plain" }, "Not found");
  }
});

server.listen(PORT, () => console.log(`Mock ID.me listening on http://localhost:${PORT}`));
