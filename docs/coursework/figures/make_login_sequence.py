"""Regenerate login_mfa_sequence.png (needs Pillow). Matches kura/views.py login_view and mfa_verify_view."""
from PIL import Image, ImageDraw, ImageFont

actors = [
    ("B", "User Browser\\n(TLS 1.3)"),
    ("N", "Nginx + Coraza WAF\\n(Rate Limit + CRS)"),
    ("D", "Django Auth Views\\n(Axes + RBAC)"),
    ("V", "HashiCorp Vault\\n(Transit Engine)"),
    ("P", "PostgreSQL 17\\n(RLS + UserSession)"),
]
# (from, to, label, dashed); from == to is a note on that lifeline.
steps = [
    ("B", "N", "1. GET /login/ (HTTPS TLS 1.3)", False),
    ("N", "D", "2. Forward over mTLS -> issue __Host-kura_csrf + CSP nonce", False),
    ("B", "N", "3. POST /login/ (email, password, csrfmiddlewaretoken)", False),
    ("N", "D", "4. Nginx limit_req + CRS inspect -> forward mTLS", False),
    ("D", "P", "5. Lookup user + Argon2id verify (or constant-time dummy hash)", False),
    ("D", "D", "6. Store pre_mfa_user_id + pre_mfa_started_at in session\\n(5 min window; no session cycle, not logged in yet)", False),
    ("D", "B", "7. 302 Redirect -> /login/mfa/ (second factor required)", True),
    ("B", "D", "8. POST /login/mfa/ (6-digit TOTP code or WebAuthn passkey)", False),
    ("D", "V", "9. Transit decrypt TOTP seed ciphertext (AppRole over TLS)", False),
    ("V", "D", "10. Plaintext seed in RAM only -> verify TOTP & drift/throttle", True),
    ("D", "P", "11. login() issues new session ID + INSERT tracked UserSession (HMAC hash)", False),
    ("D", "B", "12. 302 -> Dashboard + Set-Cookie: __Host-kura_session (HttpOnly; Secure; SameSite=Lax)", True),
]


FD = "/usr/share/fonts/truetype/dejavu/DejaVuSans%s.ttf"
f_t, f_b, f_s = (ImageFont.truetype(FD % "-Bold", 30), ImageFont.truetype(FD % "-Bold", 19), ImageFont.truetype(FD % "", 15))
W, H, TOP, ROW = 2000, 1150, 190, 78
xs = {a: 190 + i * 405 for i, (a, _) in enumerate(actors)}
img = Image.new("RGB", (W, H), "white")
d = ImageDraw.Draw(img)
d.text((W // 2, 45), "Kura Secure LMS: Two-Step Authentication, Vault Transit MFA & __Host- Session Sequence", font=f_t, fill="#0f172a", anchor="mm")
for a, t in actors:
    x = xs[a]
    l1, l2 = t.split("\\n")
    d.rounded_rectangle((x - 155, 90, x + 155, 175), 12, fill="#eef5ff", outline="#1d4ed8", width=3)
    d.text((x, 118), l1, font=f_b, fill="#1e3a8a", anchor="mm")
    d.text((x, 150), l2, font=f_s, fill="#475569", anchor="mm")
    for y in range(TOP, H - 30, 14):
        d.line((x, y, x, y + 8), fill="#94a3b8", width=2)


def arrow(x1, x2, y, col, dashed):
    sgn = 1 if x2 > x1 else -1
    if dashed:
        for x in range(min(x1, x2), max(x1, x2) - 14, 16):
            d.line((x, y, x + 9, y), fill=col, width=3)
        d.line((x1 + sgn * 0, y, x2, y), fill=col, width=0)
    else:
        d.line((x1, y, x2, y), fill=col, width=3)
    d.polygon([(x2, y), (x2 - sgn * 16, y - 7), (x2 - sgn * 16, y + 7)], fill=col)


for i, (f, t, lab, dashed) in enumerate(steps):
    y = TOP + 40 + i * ROW
    col = "#0369a1" if dashed else "#1e293b"
    if f == t:
        lines = lab.split("\\n")
        w = max(d.textlength(line, font=f_b) for line in lines) + 30
        x0 = xs[f] + 25
        d.line((xs[f], y, x0, y), fill="#047857", width=3)
        d.rectangle((x0, y - 28, x0 + w, y - 28 + 20 + 26 * len(lines)), fill="#ecfdf3", outline="#047857", width=2)
        for k, line in enumerate(lines):
            d.text((x0 + 15, y - 14 + k * 26), line, font=f_b, fill="#065f46")
        continue
    x1, x2 = xs[f], xs[t]
    arrow(x1, x2, y, col, dashed)
    d.text(((x1 + x2) / 2, y - 14), lab, font=f_b, fill=col, anchor="mm")
img.save("login_mfa_sequence.png")

