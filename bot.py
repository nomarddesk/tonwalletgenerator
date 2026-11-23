"""
TON Wallet Bot (aiogram 3, single file)

Commands (admin only, private chat):
  /new 20         make 20 new multichain wallets (#1, #2, #3 ...)
  /seed 5         show the seed + addresses of wallet #5 again
  /balance 1 20   show TON balance of wallets #1 to #20
  /hop 1 20       move ALL TON from #1 -> #2 -> #3 ... -> #20 (asks to confirm first)
  /stop           stop a running hop after the current transfer

Wallets:
- 12-word multichain seeds (BIP-39). Import into Keeper (Tonkeeper) and the wallet
  shows the MULTICHAIN label, with TON, TRON, ETH/BNB/Base/Arbitrum and BTC addresses.
- Every wallet is built from MASTER_SECRET + its number. The bot never saves seeds;
  it rebuilds them from the secret when it needs to sign. The database (SQLite) only
  keeps wallet numbers and TON addresses.
- KEEP MASTER_SECRET SAFE AND BACKED UP. Anyone who has it controls every wallet.
  If you lose it, the bot can't move funds (the seeds you saved still work in Keeper).
  Never change it after making wallets: the bot refuses to run if it doesn't match.

Env vars:
  BOT_TOKEN            required. Token from @BotFather
  ADMIN_IDS            required. Comma list of Telegram user IDs
  MASTER_SECRET        required. 64 hex characters. Make one with:
                       python -c "import secrets; print(secrets.token_hex(32))"
  NETWORK              optional. "mainnet" (default) or "testnet"
  TONCENTER_API_KEY    optional but recommended. Free key from @tonapibot.
                       Without it the bot is limited to about 1 request per second.
  DB_PATH              optional. Default /data/wallets-<network>.db (Railway volume at /data)
  MAX_WALLETS          optional. Max wallets per /new (default 50)
  MAX_HOPS             optional. Max transfers per /hop (default 100)
  MIN_HOP_TON          optional. Stop if a wallet has less than this (default 0.02)
  AUTO_DELETE_SECONDS  optional. Delete seed messages after this many seconds
                       (default 300, 0 = never)
"""

import asyncio
import hashlib
import hmac
import logging
import os
import sqlite3
import time
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

from aiogram import Bot, Dispatcher, F
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ChatType, ParseMode
from aiogram.filters import Command, CommandObject, CommandStart
from aiogram.types import (
    BufferedInputFile,
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)
from Cryptodome.Hash import RIPEMD160, keccak
from ecdsa import SECP256k1, SigningKey
from ton_core import ContractState, MnemonicType, NetworkGlobalID, SendMode, WalletV5Params
from ton_core.contrib.utils import ton_mnemonic_is_valid
from ton_core.contrib.utils import words as BIP39_WORDS
from tonutils.clients import ToncenterClient
from tonutils.contracts import WalletV5R1

# ================================================================ settings

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
ADMIN_IDS = {int(x) for x in os.getenv("ADMIN_IDS", "").replace(" ", "").split(",") if x}
_MASTER_HEX = os.getenv("MASTER_SECRET", "").strip().lower()
NETWORK = os.getenv("NETWORK", "mainnet").strip().lower()
TONCENTER_API_KEY = os.getenv("TONCENTER_API_KEY", "").strip() or None
MAX_WALLETS = int(os.getenv("MAX_WALLETS", "50"))
MAX_HOPS = int(os.getenv("MAX_HOPS", "100"))
MIN_HOP_TON = float(os.getenv("MIN_HOP_TON", "0.02"))
AUTO_DELETE_SECONDS = int(os.getenv("AUTO_DELETE_SECONDS", "300"))

if not BOT_TOKEN:
    raise SystemExit("BOT_TOKEN is missing")
if not ADMIN_IDS:
    raise SystemExit("ADMIN_IDS is missing. Without it anyone could use the bot.")
if NETWORK not in ("mainnet", "testnet"):
    raise SystemExit('NETWORK must be "mainnet" or "testnet"')
try:
    MASTER_SECRET = bytes.fromhex(_MASTER_HEX)
except ValueError:
    MASTER_SECRET = b""
if len(MASTER_SECRET) != 32:
    raise SystemExit(
        "MASTER_SECRET must be 64 hex characters. Make one on your own computer with:\n"
        '  python -c "import secrets; print(secrets.token_hex(32))"'
    )

IS_TESTNET = NETWORK == "testnet"
NET_ID = NetworkGlobalID.TESTNET if IS_TESTNET else NetworkGlobalID.MAINNET
EXPLORER = "https://testnet.tonviewer.com/" if IS_TESTNET else "https://tonviewer.com/"
DB_PATH = os.getenv("DB_PATH") or (
    f"/data/wallets-{NETWORK}.db" if Path("/data").is_dir() else f"wallets-{NETWORK}.db"
)

NANO = 1_000_000_000
MIN_HOP_NANO = int(MIN_HOP_TON * NANO)
# Send whole balance (128). W5 wallets also require "ignore errors" (2) on every send.
SEND_ALL = SendMode.CARRY_ALL_REMAINING_BALANCE | SendMode.IGNORE_ERRORS
TX_TTL = 120        # a signed transfer expires after this many seconds, so it can't go through late
POLL_SECONDS = 4    # how often to check if TON arrived
ARRIVAL_GRACE = 30  # after a transfer expires, keep watching this many seconds more
MAX_AS_MESSAGES = 5 # up to this many wallets go out as messages, more = one .txt file

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("tonbot")  # seeds are never logged

dp = Dispatcher()
_background_tasks: set[asyncio.Task] = set()
client: ToncenterClient | None = None  # set in main()
HOP = {"running": False, "stop": False}


# ================================================================ wallet seeds

def _entropy_to_words(entropy: bytes) -> list[str]:
    """Standard BIP-39: entropy + checksum bits -> words."""
    bits = "".join(f"{b:08b}" for b in entropy)
    bits += f"{hashlib.sha256(entropy).digest()[0]:08b}"[: len(entropy) * 8 // 32]
    return [BIP39_WORDS[int(bits[i : i + 11], 2)] for i in range(0, len(bits), 11)]


def wallet_words(n: int) -> list[str]:
    """12-word seed for wallet #n, always the same for the same MASTER_SECRET.

    Seeds that also pass as old-style TON seeds are skipped, so Keeper always
    reads them as multichain.
    """
    attempt = 0
    while True:
        msg = f"ton-wallet-bot/{NETWORK}/{n}/{attempt}".encode()
        entropy = hmac.new(MASTER_SECRET, msg, hashlib.sha512).digest()[:16]
        words = _entropy_to_words(entropy)
        if not ton_mnemonic_is_valid(words):
            return words
        attempt += 1


class _Offline:
    """Stand-in client: only gives the network, never goes online."""
    network = NET_ID


def ton_wallet(words: list[str], ton_client=None) -> WalletV5R1:
    """W5 wallet from a multichain seed (path m/44'/607'/0', same as Keeper)."""
    wallet, *_ = WalletV5R1.from_mnemonic(
        ton_client or _Offline(), words, mnemonic_type=MnemonicType.MULTICHAIN
    )
    return wallet


def fmt_addr(address) -> str:
    """UQ... on mainnet, 0Q... on testnet (non-bounceable, what wallets show)."""
    return address.to_str(is_bounceable=False, is_test_only=IS_TESTNET)


# ================================================================ other chains
# Same paths Keeper uses (tonkeeper-web: chains/derivation.ts):
#   EVM  m/44'/60'/0'/0/0   (one 0x address for ETH, BNB Chain, Base, Arbitrum)
#   TRON m/44'/195'/0'/0/0
#   BTC  m/84'/0'/0'/0/0    (native segwit, bc1q...)

H = 0x80000000
CURVE_N = SECP256k1.order
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def bip39_seed(words: list[str]) -> bytes:
    phrase = unicodedata.normalize("NFKD", " ".join(words))
    return hashlib.pbkdf2_hmac("sha512", phrase.encode(), b"mnemonic", 2048)


def secp_pub(priv: bytes, compressed: bool = True) -> bytes:
    vk = SigningKey.from_string(priv, curve=SECP256k1).get_verifying_key()
    return vk.to_string("compressed" if compressed else "uncompressed")


def bip32_key(seed: bytes, path: list[int]) -> bytes:
    """BIP-32 secp256k1 private key for a path."""
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    key, chain = digest[:32], digest[32:]
    for index in path:
        data = (b"\x00" + key) if index & H else secp_pub(key)
        digest = hmac.new(chain, data + index.to_bytes(4, "big"), hashlib.sha512).digest()
        tweak = int.from_bytes(digest[:32], "big")
        child = (tweak + int.from_bytes(key, "big")) % CURVE_N
        if tweak >= CURVE_N or child == 0:  # odds are about 1 in 2^127
            raise ValueError("invalid child key")
        key, chain = child.to_bytes(32, "big"), digest[32:]
    return key


def keccak256(data: bytes) -> bytes:
    return keccak.new(digest_bits=256, data=data).digest()


def evm_raw(priv: bytes) -> bytes:
    return keccak256(secp_pub(priv, compressed=False)[1:])[-20:]


def evm_address(priv: bytes) -> str:
    """0x address with EIP-55 mixed-case checksum."""
    hex_addr = evm_raw(priv).hex()
    check = keccak256(hex_addr.encode()).hex()
    return "0x" + "".join(c.upper() if int(check[i], 16) >= 8 else c for i, c in enumerate(hex_addr))


def base58check(payload: bytes) -> str:
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    num, out = int.from_bytes(data, "big"), ""
    while num:
        num, rem = divmod(num, 58)
        out = B58[rem] + out
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + out


def tron_address(priv: bytes) -> str:
    return base58check(b"\x41" + evm_raw(priv))


def _bech32_polymod(values: list[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def btc_segwit_address(priv: bytes) -> str:
    """bc1q... native segwit (P2WPKH, BIP-173 bech32)."""
    h160 = RIPEMD160.new(hashlib.sha256(secp_pub(priv)).digest()).digest()
    acc, bits, data = 0, 0, [0]  # 0 = witness version
    for b in h160:  # 8-bit -> 5-bit groups
        acc, bits = (acc << 8) | b, bits + 8
        while bits >= 5:
            bits -= 5
            data.append((acc >> bits) & 31)
    if bits:
        data.append((acc << (5 - bits)) & 31)
    hrp = "bc"
    expanded = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    mod = _bech32_polymod(expanded + data + [0] * 6) ^ 1
    checksum = [(mod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(BECH32[d] for d in data + checksum)


def wallet_info(n: int) -> dict:
    """Seed + all addresses for wallet #n."""
    words = wallet_words(n)
    info = {"n": n, "seed": " ".join(words), "ton": fmt_addr(ton_wallet(words).address)}
    if not IS_TESTNET:  # other chains only make sense on mainnet
        seed = bip39_seed(words)
        info["tron"] = tron_address(bip32_key(seed, [44 | H, 195 | H, 0 | H, 0, 0]))
        info["evm"] = evm_address(bip32_key(seed, [44 | H, 60 | H, 0 | H, 0, 0]))
        info["btc"] = btc_segwit_address(bip32_key(seed, [84 | H, 0 | H, 0 | H, 0, 0]))
    return info


# ================================================================ database
# Only wallet numbers and TON addresses. Nothing secret.

_db = sqlite3.connect(DB_PATH, check_same_thread=False)
_db.execute("CREATE TABLE IF NOT EXISTS wallets (n INTEGER PRIMARY KEY, ton TEXT NOT NULL, created_at TEXT NOT NULL)")
_db.commit()


def db_max() -> int:
    return _db.execute("SELECT COALESCE(MAX(n), 0) FROM wallets").fetchone()[0]


def db_address(n: int) -> str | None:
    row = _db.execute("SELECT ton FROM wallets WHERE n = ?", (n,)).fetchone()
    return row[0] if row else None


def db_add(infos: list[dict]) -> None:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    _db.executemany(
        "INSERT OR REPLACE INTO wallets (n, ton, created_at) VALUES (?, ?, ?)",
        [(w["n"], w["ton"], now) for w in infos],
    )
    _db.commit()


def check_master_secret() -> None:
    """Refuse to run if MASTER_SECRET was changed after wallets were made."""
    saved = db_address(1)
    if saved and saved != fmt_addr(ton_wallet(wallet_words(1)).address):
        raise SystemExit(
            "MASTER_SECRET does not match the saved wallets. "
            "Put back the secret you used when you made them."
        )


def signing_wallet(n: int) -> WalletV5R1:
    """Wallet #n connected to the network, after checking it matches the database."""
    wallet = ton_wallet(wallet_words(n), client)
    if fmt_addr(wallet.address) != db_address(n):
        raise RuntimeError(f"wallet #{n} does not match the database")
    return wallet


# ================================================================ TON network

def ton_str(nano: int) -> str:
    return f"{nano / NANO:.4f}".rstrip("0").rstrip(".")


def short(addr: str) -> str:
    return f"{addr[:6]}…{addr[-4:]}"


def link(addr: str, text: str | None = None) -> str:
    return f'<a href="{EXPLORER}{addr}">{text or short(addr)}</a>'


async def get_info(address: str):
    """Balance + state, with a few retries for network hiccups."""
    for attempt in range(4):
        try:
            return await client.get_info(address)
        except Exception:
            if attempt == 3:
                raise
            await asyncio.sleep(2 * (attempt + 1))


async def wait_for_arrival(address: str, before: int, deadline: float) -> int | None:
    """Wait until the balance goes above `before`. Returns the new balance, or None on timeout."""
    while time.time() < deadline:
        await asyncio.sleep(POLL_SECONDS)
        try:
            info = await get_info(address)
        except Exception:
            continue
        if info.balance > before:
            return info.balance
    return None


async def safe_edit(msg: Message, text: str) -> None:
    try:
        await msg.edit_text(text, disable_web_page_preview=True)
    except Exception:
        pass  # "message is not modified" and similar


async def hop_chain(bot: Bot, chat_id: int, start: int, end: int) -> None:
    """Move all TON from #start through each wallet to #end, one transfer at a time."""
    step = 1 if end > start else -1
    numbers = list(range(start, end + step, step))
    total = len(numbers) - 1
    lines: list[str] = []
    fees = 0
    at = start  # where the TON is right now
    head = f"<b>Hop #{start} → #{end}</b> ({total} transfers)"
    status = await bot.send_message(chat_id, head + "\n\nStarting...")

    try:
        for i in range(total):
            a, b = numbers[i], numbers[i + 1]
            if HOP["stop"]:
                result = f"⏹ Stopped by you. The TON is in wallet #{at}."
                break

            src = signing_wallet(a)
            dst = db_address(b)
            src_info = await get_info(db_address(a))  # raises on network errors (no silent zero)
            balance = src_info.balance
            if src_info.state == ContractState.FROZEN:
                result = f"⚠️ Wallet #{a} is frozen. Stopped."
                break
            if balance < MIN_HOP_NANO:
                result = (f"⚠️ Wallet #{a} has only {ton_str(balance)} TON "
                          f"(need at least {MIN_HOP_TON:g}). Stopped at #{a}.")
                break

            dst_before = (await get_info(dst)).balance
            valid_until = int(time.time()) + TX_TTL
            await safe_edit(status, head + "\n\n" + "\n".join(lines[-10:]) +
                            f"\n\n⏳ #{a} → #{b}: sending {ton_str(balance)} TON...")
            try:
                await src.transfer(
                    destination=dst,
                    amount=0,              # with SEND_ALL, the whole balance goes
                    send_mode=SEND_ALL,
                    bounce=False,          # new wallets are not deployed yet
                    params=WalletV5Params(valid_until=valid_until),
                )
            except Exception as e:
                log.warning("send from #%s failed: %s", a, e)
                result = (f"❌ Could not send from #{a} ({type(e).__name__}). "
                          f"Check {link(db_address(a), f'#{a}')} and run "
                          f"/hop {a} {end} again.")
                break

            arrived = await wait_for_arrival(dst, dst_before, valid_until + ARRIVAL_GRACE)
            if arrived is None:
                result = (f"⚠️ #{a} → #{b} not confirmed in time. The transfer has expired, so it "
                          f"can't go through later. Check {link(db_address(a), f'#{a}')} and "
                          f"{link(dst, f'#{b}')}: if the TON is still in #{a}, run /hop {a} {end}. "
                          f"If it reached #{b}, run /hop {b} {end}.")
                break

            received = arrived - dst_before
            fees += balance - received
            at = b
            lines.append(f"#{a} → #{b}: {ton_str(received)} TON ✅")
            await safe_edit(status, head + "\n\n" + "\n".join(lines[-10:]) + f"\n\n{i + 1}/{total} done")
        else:
            result = f"✅ Done. All TON is now in wallet #{end}."
    except Exception as e:
        log.exception("hop failed")
        result = (f"❌ Error: {type(e).__name__}. The TON should be in wallet #{at} "
                  f"(or the next one). Check the explorer, then resume with /hop {at} {end}.")
    finally:
        HOP["running"] = False
        HOP["stop"] = False

    final = db_address(at)
    summary = [head, ""]
    if lines:
        summary += lines[-30:] if len(lines) <= 30 else [f"... {len(lines) - 30} earlier hops", *lines[-30:]]
        summary += ["", f"Network fees: {ton_str(fees)} TON"]
    summary += [result, f"Now in: {link(final, f'#{at} ' + short(final))}"]
    await safe_edit(status, "\n".join(summary))


def start_background(coro) -> None:
    task = asyncio.create_task(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)


# ================================================================ message helpers

ADDRESS_ROWS = [
    ("ton", "TON (W5)"),
    ("tron", "TRON (USDT TRC-20)"),
    ("evm", "ETH / BNB / Base / Arbitrum"),
    ("btc", "BTC (segwit)"),
]


def wallet_message(w: dict) -> str:
    lines = [
        f"<b>Wallet #{w['n']}</b> (Multichain{', TESTNET' if IS_TESTNET else ''})",
        "",
        "<b>Seed phrase</b> (12 words, tap to copy):",
        f"<code>{w['seed']}</code>",
    ]
    for key, label in ADDRESS_ROWS:
        if key in w:
            lines += ["", f"<b>{label}</b>", f"<code>{w[key]}</code>"]
    return "\n".join(lines)


def wallet_file_text(wallets: list[dict], stamp: str) -> str:
    net = " TESTNET" if IS_TESTNET else ""
    lines = [f"Multichain{net} wallets #{wallets[0]['n']}-#{wallets[-1]['n']}, made {stamp} UTC", ""]
    for w in wallets:
        lines += [f"#{w['n']}", f"Seed: {w['seed']}"]
        lines += [f"{label}: {w[key]}" for key, label in ADDRESS_ROWS if key in w]
        lines.append("")
    return "\n".join(lines)


def is_admin(message: Message) -> bool:
    return message.from_user is not None and message.from_user.id in ADMIN_IDS


async def delete_later(bot: Bot, chat_id: int, message_ids: list[int], seconds: int) -> None:
    """Delete seed messages after a delay. If the bot restarts first, they stay."""
    await asyncio.sleep(seconds)
    for mid in message_ids:
        try:
            await bot.delete_message(chat_id, mid)
        except Exception:
            pass


async def send_seeds(message: Message, bot: Bot, wallets: list[dict]) -> None:
    """Send wallets (messages or a .txt file), then schedule auto-delete."""
    sent: list[int] = []
    if len(wallets) <= MAX_AS_MESSAGES:
        for w in wallets:
            sent.append((await message.answer(wallet_message(w))).message_id)
    else:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        file = BufferedInputFile(wallet_file_text(wallets, stamp).encode(), filename=f"wallets-{stamp}.txt")
        caption = f"Wallets #{wallets[0]['n']} to #{wallets[-1]['n']}"
        sent.append((await message.answer_document(file, caption=caption)).message_id)

    if AUTO_DELETE_SECONDS > 0:
        mins, secs = divmod(AUTO_DELETE_SECONDS, 60)
        when = f"{mins} min" if secs == 0 else f"{AUTO_DELETE_SECONDS} sec"
        note = await message.answer(f"These delete themselves in {when}. Save the seeds now "
                                    f"(you can get any one back later with /seed).")
        sent.append(note.message_id)
        start_background(delete_later(bot, message.chat.id, sent, AUTO_DELETE_SECONDS))


def numbers_from(args: str | None) -> list[int] | None:
    """'1 20' or '1-20' -> [1, 20]. None if something isn't a number."""
    parts = (args or "").replace("-", " ").split()
    if not all(p.isdigit() for p in parts):
        return None
    return [int(p) for p in parts]


# ================================================================ commands

dp.message.filter(F.chat.type == ChatType.PRIVATE)  # never post seeds in a group


@dp.message(CommandStart())
@dp.message(Command("help"))
async def start(message: Message) -> None:
    if not is_admin(message):
        await message.answer("This bot is private.")
        return
    net = "\n⚠️ <b>TESTNET mode</b> (test TON, no real value)\n" if IS_TESTNET else ""
    await message.answer(
        f"<b>TON Wallet Bot</b>{net}\n"
        "<code>/new 20</code> — make 20 new wallets\n"
        "<code>/seed 5</code> — show wallet #5 again\n"
        "<code>/balance 1 20</code> — TON balance of #1 to #20\n"
        "<code>/hop 1 20</code> — move ALL TON #1 → #2 → … → #20\n"
        "<code>/stop</code> — stop a running hop\n\n"
        f"Wallets made so far: <b>{db_max()}</b>\n\n"
        "Each wallet has a 12-word seed. In Keeper it shows the MULTICHAIN label."
    )


@dp.message(Command("new"))
async def new_wallets(message: Message, command: CommandObject, bot: Bot) -> None:
    if not is_admin(message):
        await message.answer("This bot is private.")
        return
    nums = numbers_from(command.args)
    count = nums[0] if nums else 1
    if nums is None or len(nums) > 1 or not 1 <= count <= MAX_WALLETS:
        await message.answer(f"Example: <code>/new 20</code> (1 to {MAX_WALLETS}).")
        return

    first = db_max() + 1
    status = await message.answer(f"Making wallets #{first} to #{first + count - 1}...")
    wallets = await asyncio.to_thread(lambda: [wallet_info(n) for n in range(first, first + count)])
    db_add(wallets)
    await send_seeds(message, bot, wallets)
    await status.delete()
    log.info("Made wallets #%s-#%s", first, first + count - 1)


@dp.message(Command("seed"))
async def seed_cmd(message: Message, command: CommandObject, bot: Bot) -> None:
    if not is_admin(message):
        return
    nums = numbers_from(command.args)
    if not nums or len(nums) != 1 or not db_address(nums[0]):
        await message.answer(f"Example: <code>/seed 5</code>. Wallets made: 1 to {db_max()}.")
        return
    info = await asyncio.to_thread(wallet_info, nums[0])
    if info["ton"] != db_address(nums[0]):
        await message.answer("❌ MASTER_SECRET does not match this wallet. Not showing anything.")
        return
    await send_seeds(message, bot, [info])


@dp.message(Command("balance"))
async def balance_cmd(message: Message, command: CommandObject) -> None:
    if not is_admin(message):
        return
    top = db_max()
    nums = numbers_from(command.args)
    if nums is None or len(nums) > 2:
        await message.answer("Example: <code>/balance 1 20</code>")
        return
    a = nums[0] if nums else 1
    b = nums[1] if len(nums) == 2 else (a if nums else min(top, 20))
    a, b = min(a, b), max(a, b)
    if top == 0 or a < 1 or b > top or b - a >= 50:
        await message.answer(f"Pick wallets between 1 and {top}, at most 50 at a time.")
        return

    status = await message.answer(f"Checking #{a} to #{b}...")
    rows, total = [], 0
    for n in range(a, b + 1):
        addr = db_address(n)
        try:
            bal = (await get_info(addr)).balance
            total += bal
            rows.append(f"#{n} {link(addr)} — <b>{ton_str(bal)}</b> TON")
        except Exception:
            rows.append(f"#{n} {link(addr)} — couldn't check")
    await safe_edit(status, "\n".join(rows) + f"\n\nTotal: <b>{ton_str(total)} TON</b>")


@dp.message(Command("hop"))
async def hop_cmd(message: Message, command: CommandObject) -> None:
    if not is_admin(message):
        return
    top = db_max()
    nums = numbers_from(command.args)
    if not nums or len(nums) != 2:
        await message.answer("Example: <code>/hop 1 20</code> moves all TON from #1 through each wallet to #20.")
        return
    a, b = nums
    if a == b or min(a, b) < 1 or max(a, b) > top:
        await message.answer(f"Use two different wallets between 1 and {top}.")
        return
    if abs(b - a) > MAX_HOPS:
        await message.answer(f"Max {MAX_HOPS} transfers per hop.")
        return
    if HOP["running"]:
        await message.answer("A hop is already running. Send /stop to stop it.")
        return

    try:
        bal = (await get_info(db_address(a))).balance
    except Exception as e:
        await message.answer(f"❌ Couldn't reach the TON network ({type(e).__name__}). Try again.")
        return
    if bal < MIN_HOP_NANO:
        await message.answer(f"Wallet #{a} has {ton_str(bal)} TON. It needs at least {MIN_HOP_TON:g} TON.\n"
                             f"Send TON to: <code>{db_address(a)}</code>")
        return

    buttons = InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="✅ Start", callback_data=f"hop:{a}:{b}"),
        InlineKeyboardButton(text="❌ Cancel", callback_data="hop:cancel"),
    ]])
    await message.answer(
        f"Move <b>ALL</b> TON from wallet #{a} through every wallet to #{b}?\n\n"
        f"Wallet #{a} has <b>{ton_str(bal)} TON</b>.\n"
        f"{abs(b - a)} transfers, about 10–20 seconds each, small network fee on each.",
        reply_markup=buttons,
    )


@dp.callback_query(F.data.startswith("hop:"))
async def hop_button(cb: CallbackQuery, bot: Bot) -> None:
    if cb.from_user.id not in ADMIN_IDS:
        await cb.answer("Not allowed.", show_alert=True)
        return
    if cb.data == "hop:cancel":
        await cb.message.edit_text("Cancelled.")
        await cb.answer()
        return
    if HOP["running"]:
        await cb.answer("A hop is already running.", show_alert=True)
        return
    HOP["running"], HOP["stop"] = True, False  # set before any await: no double start
    _, a, b = cb.data.split(":")
    await cb.answer("Started")
    await cb.message.edit_text(f"Started: #{a} → #{b}")
    log.info("Hop #%s -> #%s started", a, b)
    start_background(hop_chain(bot, cb.message.chat.id, int(a), int(b)))


@dp.message(Command("stop"))
async def stop_cmd(message: Message) -> None:
    if not is_admin(message):
        return
    if not HOP["running"]:
        await message.answer("Nothing is running.")
        return
    HOP["stop"] = True
    await message.answer("OK. It will stop after the current transfer.")


@dp.message()
async def fallback(message: Message) -> None:
    if is_admin(message):
        await message.answer("Send /help to see the commands.")


# ================================================================ run

async def main() -> None:
    global client
    check_master_secret()
    client = ToncenterClient(network=NET_ID, api_key=TONCENTER_API_KEY)
    await client.connect()
    bot = Bot(BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    log.info("Bot started on %s. DB: %s. Wallets: %s", NETWORK, DB_PATH, db_max())
    if not TONCENTER_API_KEY:
        log.info("No TONCENTER_API_KEY: limited to about 1 request per second")
    try:
        await dp.start_polling(bot)
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
