# ============================================================
# OVEX Key Bot v2.0 - PREFIX KOMUTLARI (!) + HTTP API
# KULLANIM: !keyolustur 30 | !keyiptal OVEX-XXX | !keylist
# ============================================================
# 1. https://discord.com/developers/applications -> New App -> Bot
# 2. Token: DISCORD_TOKEN ortam degiskenine yaz
# 3. Bot'u sunucuna ekle (scope: bot, permissions: 3072)
# 4. Calistir: python bot.py
# ============================================================
import discord
from discord.ext import commands
import sqlite3, secrets, string, os, datetime, asyncio
from aiohttp import web

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bot_debug.log")
def log(msg):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{datetime.datetime.now().strftime('%H:%M:%S')} {msg}\n")
    print(msg, flush=True)

log("OVEX Key Bot basliyor...")
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys.db")
DISCORD_TOKEN = os.environ.get("DISCORD_TOKEN", "")
ALLOWED_USER = int(os.environ.get("ALLOWED_USER", "0") or "0")
API_PORT = int(os.environ.get("PORT", 8080))

# === SQLite ===
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS keys (
        key_id TEXT PRIMARY KEY, hwid TEXT DEFAULT '',
        created_by TEXT DEFAULT '', created_at TEXT DEFAULT '',
        expires_at TEXT DEFAULT '', revoked INTEGER DEFAULT 0
    )""")
    conn.commit(); conn.close()

def db_add_key(key_id, created_by, days):
    now = datetime.datetime.utcnow()
    expires = now + datetime.timedelta(days=days)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO keys VALUES (?,?,?,?,?,0)",
              (key_id, "", str(created_by), now.isoformat(), expires.isoformat()))
    conn.commit(); conn.close()

def db_revoke_key(key_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE keys SET revoked=1 WHERE key_id=?", (key_id,))
    n = c.rowcount; conn.commit(); conn.close()
    return n > 0

def db_list_keys():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT key_id, hwid, created_at, expires_at, revoked FROM keys ORDER BY created_at DESC")
    rows = c.fetchall(); conn.close()
    return rows

def db_verify_key(key_id, hwid):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT hwid, expires_at, revoked FROM keys WHERE key_id=?", (key_id,))
    row = c.fetchone(); conn.close()
    if not row: return "invalid"
    db_hwid, expires_at, revoked = row
    if revoked: return "revoked"
    if datetime.datetime.fromisoformat(expires_at) < datetime.datetime.utcnow(): return "expired"
    if db_hwid == "":
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("UPDATE keys SET hwid=? WHERE key_id=?", (hwid, key_id))
        conn.commit(); conn.close()
        return "ok"
    return "ok" if db_hwid == hwid else "hwid_mismatch"

def gen_key_id():
    return "OVEX-" + ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))

def check_auth_msg(msg):
    if ALLOWED_USER and msg.author.id != ALLOWED_USER:
        return False
    return True

# === Discord Bot (prefix commands) ===
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)

@bot.event
async def on_ready():
    log(f"Bot baglandi: {bot.user} | {len(bot.guilds)} sunucu")
    for g in bot.guilds:
        log(f"  -> {g.name} ({g.id})")
    # Slash komutlarini sync etme (kullanmiyoruz)
    log("Bot hazir! Prefix komut: !keyolustur !keyiptal !keylist")

@bot.command(name="keyolustur")
async def keyolustur(ctx, gun: int, *, isim: str = ""):
    if not check_auth_msg(ctx.message): return
    if gun < 1 or gun > 3650:
        await ctx.send("Gun sayisi 1-3650 arasi olmali!")
        return
    key_id = gen_key_id()
    db_add_key(key_id, ctx.author.id, gun)
    bitis = (datetime.datetime.utcnow() + datetime.timedelta(days=gun)).strftime("%Y-%m-%d")
    embed = discord.Embed(title="Yeni Key Olusturuldu", color=0x7B68EE)
    embed.add_field(name="Key", value=f"`{key_id}`", inline=False)
    embed.add_field(name="Gecerlilik", value=f"{gun} gun (bitis: {bitis})", inline=True)
    if isim: embed.add_field(name="Etiket", value=isim, inline=True)
    await ctx.send(embed=embed)
    log(f"keyolustur: gun={gun}, key={key_id}, user={ctx.author}")

@bot.command(name="keyiptal")
async def keyiptal(ctx, key: str):
    if not check_auth_msg(ctx.message): return
    if db_revoke_key(key.upper()):
        await ctx.send(f"`{key}` iptal edildi!")
    else:
        await ctx.send(f"`{key}` bulunamadi!")
    log(f"keyiptal: {key}, user={ctx.author}")

@bot.command(name="keylist")
async def keylist(ctx):
    if not check_auth_msg(ctx.message): return
    rows = db_list_keys()
    if not rows:
        await ctx.send("Henuz key yok.")
        return
    lines = []
    for key_id, hwid, created_at, expires_at, revoked in rows[:25]:
        durum = "IPTAL" if revoked else "AKTIF"
        hwid_short = hwid[:16] + "..." if len(hwid) > 16 else (hwid if hwid else "KULLANILMADI")
        kaldi = (datetime.datetime.fromisoformat(expires_at) - datetime.datetime.utcnow()).days
        lines.append(f"`{key_id}` | {durum} | Kalan:{kaldi} gun | HWID:{hwid_short}")
    await ctx.send("```" + "\n".join(lines) + "```")

# === HTTP API ===
async def handle_verify(request):
    try:
        body = await request.json()
        key = body.get("key", "").upper().strip()
        hwid = body.get("hwid", "").strip()
        if not key or not hwid:
            return web.json_response({"status": "invalid", "msg": "Eksik parametre"}, status=400)
        return web.json_response({"status": db_verify_key(key, hwid)})
    except Exception as e:
        return web.json_response({"status": "error", "msg": str(e)}, status=500)

async def handle_index(request):
    return web.json_response({"status": "OVEX Key Bot running", "endpoints": ["/verify"]})

async def run_api():
    app = web.Application()
    app.router.add_get("/", handle_index)
    app.router.add_post("/verify", handle_verify)
    runner = web.AppRunner(app); await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", API_PORT); await site.start()
    log(f"API baslatildi: 0.0.0.0:{API_PORT}")

async def main():
    init_db(); await run_api()
    if DISCORD_TOKEN:
        log("Discord'a baglaniyor...")
        while True:
            try:
                await bot.start(DISCORD_TOKEN, reconnect=True)
            except Exception as e:
                log(f"Bot hatasi: {e}, 30sn sonra yeniden...")
                await asyncio.sleep(30)
    else:
        while True: await asyncio.sleep(3600)

if __name__ == "__main__":
    asyncio.run(main())
