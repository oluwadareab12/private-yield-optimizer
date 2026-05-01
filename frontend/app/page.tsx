"use client";

import { useState, useEffect, useCallback } from "react";

// ─── Types ────────────────────────────────────────────────────────────────────

type Mode = "lp" | "protocol" | "auctioneer";
type Status = "idle" | "loading" | "success" | "error";

interface MatchResult {
  lpId: string;
  protocolId: string;
  clearingRate: number;
  capitalAllocated: number;
}

interface SettlementResult {
  settlementId: string;
  matches: MatchResult[];
  totalCapitalMatched: number;
  averageClearingRate: number;
  participantCount: number;
  settledAt: string;
  algorithmHash: string;
}

// ─── Crypto helpers ───────────────────────────────────────────────────────────

function toB64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

function fromB64(s: string): Uint8Array {
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

/**
 * Encrypts each numeric field independently under a shared ECDH session.
 * Pattern: X25519 ECDH → HKDF-SHA256 (field-specific info) → AES-GCM-256.
 * All fields share one IV and one ephemeral key pair; different HKDF info
 * strings ensure distinct cipher keys, so reusing the IV is safe.
 */
async function encryptOfferFields(
  fields: Record<string, number>,
  mxePubKeyB64: string
): Promise<{ encrypted: Record<string, string>; iv: string; clientPublicKey: string }> {
  const mxePub = await crypto.subtle.importKey(
    "raw",
    fromB64(mxePubKeyB64),
    { name: "X25519" } as AlgorithmIdentifier,
    false,
    []
  );

  const ephemeral = (await crypto.subtle.generateKey(
    { name: "X25519" } as AlgorithmIdentifier,
    true,
    ["deriveBits"]
  )) as CryptoKeyPair;

  const sharedBits = await crypto.subtle.deriveBits(
    { name: "X25519", public: mxePub } as AlgorithmIdentifier,
    ephemeral.privateKey,
    256
  );

  const hkdf = await crypto.subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);

  const ivBytes = crypto.getRandomValues(new Uint8Array(12));
  const iv = toB64(ivBytes);

  const clientPublicKey = toB64(
    new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey))
  );

  const encrypted: Record<string, string> = {};
  for (const [field, value] of Object.entries(fields)) {
    const aesKey = await crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(32),
        info: new TextEncoder().encode(`yield-optimizer-v1:${field}`),
      },
      hkdf,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt"]
    );
    const ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: ivBytes },
      aesKey,
      new TextEncoder().encode(String(value))
    );
    encrypted[field] = toB64(new Uint8Array(ct));
  }

  return { encrypted, iv, clientPublicKey };
}

// ─── Design tokens ────────────────────────────────────────────────────────────

const card: React.CSSProperties = {
  background: "rgba(255,255,255,0.025)",
  backdropFilter: "blur(24px)",
  WebkitBackdropFilter: "blur(24px)",
  border: "1px solid rgba(255,255,255,0.075)",
  borderRadius: "1rem",
  padding: "2rem",
};

const inputCls =
  "w-full bg-white/[0.04] border border-white/[0.12] rounded-xl px-4 py-3 text-white placeholder-slate-600 font-mono text-sm focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 transition-all duration-200";

const labelCls = "text-[10px] font-semibold text-slate-500 uppercase tracking-[0.15em]";

// ─── Reusable field components ────────────────────────────────────────────────

interface FieldProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label: string;
  hint?: string;
  accent?: "cyan" | "purple";
}

function Field({ label, hint, accent = "cyan", ...rest }: FieldProps) {
  const focusBorder = accent === "cyan" ? "focus:border-cyan-500/60 focus:ring-cyan-500/20" : "focus:border-purple-500/60 focus:ring-purple-500/20";
  return (
    <div className="flex flex-col gap-1.5">
      <label className={labelCls}>{label}</label>
      <input
        {...rest}
        className={`w-full bg-white/[0.04] border border-white/[0.12] rounded-xl px-4 py-3 text-white placeholder-slate-600 font-mono text-sm focus:outline-none focus:ring-1 transition-all duration-200 ${focusBorder}`}
      />
      {hint && <p className="text-[11px] text-slate-600">{hint}</p>}
    </div>
  );
}

function IdField({ value, onChange, accent = "cyan" }: { value: string; onChange: (v: string) => void; accent?: "cyan" | "purple" }) {
  const focusBorder = accent === "cyan" ? "focus:border-cyan-500/60 focus:ring-cyan-500/20" : "focus:border-purple-500/60 focus:ring-purple-500/20";
  return (
    <div className="flex flex-col gap-1.5">
      <label className={labelCls}>Participant ID</label>
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className={`w-full bg-white/[0.04] border border-white/[0.12] rounded-xl px-4 py-3 text-slate-400 font-mono text-xs focus:outline-none focus:ring-1 transition-all duration-200 ${focusBorder}`}
        placeholder="Auto-generated UUID"
      />
      <p className="text-[11px] text-slate-600">Save this ID — you'll need it to check your result</p>
    </div>
  );
}

function ErrorBox({ msg }: { msg: string }) {
  return (
    <div
      className="rounded-xl px-4 py-3 text-sm"
      style={{
        background: "rgba(239,68,68,0.08)",
        border: "1px solid rgba(239,68,68,0.25)",
        color: "#fca5a5",
      }}
    >
      {msg}
    </div>
  );
}

function EncryptBadge() {
  return (
    <p className="flex items-center justify-center gap-1.5 text-[11px] text-slate-600 select-none">
      <span>🔒</span>
      <span>Encrypted with X25519 + AES-GCM-256</span>
    </p>
  );
}

function Spinner() {
  return (
    <svg className="animate-spin h-4 w-4" fill="none" viewBox="0 0 24 24">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
    </svg>
  );
}

function StatBox({
  label,
  value,
  accent = "cyan",
}: {
  label: string;
  value: string;
  accent?: "cyan" | "purple";
}) {
  const border = accent === "cyan" ? "rgba(6,182,212,0.2)" : "rgba(168,85,247,0.2)";
  const color = accent === "cyan" ? "#67e8f9" : "#c084fc";
  return (
    <div
      className="rounded-xl px-3 py-2.5"
      style={{ background: "rgba(255,255,255,0.03)", border: `1px solid ${border}` }}
    >
      <p className="text-[10px] text-slate-500 mb-1 uppercase tracking-widest">{label}</p>
      <p className="font-semibold text-sm" style={{ color }}>
        {value}
      </p>
    </div>
  );
}

function SuccessCard({
  participantId,
  color,
  onReset,
}: {
  participantId: string;
  color: "cyan" | "purple";
  onReset: () => void;
}) {
  const idColor = color === "cyan" ? "#67e8f9" : "#c084fc";
  return (
    <div
      className="rounded-xl p-6 text-center"
      style={{ background: "rgba(16,185,129,0.07)", border: "1px solid rgba(16,185,129,0.22)" }}
    >
      <div className="text-4xl mb-3">✅</div>
      <p className="text-emerald-400 font-semibold text-base mb-1">Offer submitted encrypted</p>
      <p className="text-slate-500 text-sm mb-5">
        Your values are sealed inside the MXE — not visible to anyone
      </p>
      <div
        className="rounded-lg px-4 py-2.5 text-xs font-mono break-all mb-1"
        style={{
          background: "rgba(255,255,255,0.04)",
          border: "1px solid rgba(255,255,255,0.08)",
          color: idColor,
        }}
      >
        {participantId}
      </div>
      <p className="text-[11px] text-slate-600 mb-5">Your participant ID — save it</p>
      <button
        onClick={onReset}
        className="text-xs text-slate-600 hover:text-slate-300 transition-colors underline underline-offset-2"
      >
        Submit another offer
      </button>
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function Home() {
  const [mode, setMode] = useState<Mode>("lp");

  // LP form
  const [lpId, setLpId] = useState("");
  const [lpCapital, setLpCapital] = useState("");
  const [lpMinYield, setLpMinYield] = useState("");
  const [lpStatus, setLpStatus] = useState<Status>("idle");
  const [lpError, setLpError] = useState("");

  // Protocol form
  const [protocolId, setProtocolId] = useState("");
  const [protocolDemand, setProtocolDemand] = useState("");
  const [protocolMaxRate, setProtocolMaxRate] = useState("");
  const [protocolStatus, setProtocolStatus] = useState<Status>("idle");
  const [protocolError, setProtocolError] = useState("");

  // Auctioneer
  const [settleStatus, setSettleStatus] = useState<Status>("idle");
  const [settlementResult, setSettlementResult] = useState<SettlementResult | null>(null);
  const [settleError, setSettleError] = useState("");
  const [checkId, setCheckId] = useState("");
  const [checkStatus, setCheckStatus] = useState<Status>("idle");
  const [checkResult, setCheckResult] = useState<{
    participantId: string;
    matches: MatchResult[];
  } | null>(null);
  const [checkError, setCheckError] = useState("");

  useEffect(() => {
    setLpId(crypto.randomUUID());
    setProtocolId(crypto.randomUUID());
  }, []);

  const getMxePubkey = useCallback(async (): Promise<string> => {
    const res = await fetch("/api/mxe-pubkey");
    if (!res.ok) throw new Error("MXE node unreachable — is the backend running?");
    const { publicKey } = await res.json();
    return publicKey as string;
  }, []);

  // ── LP submit ──────────────────────────────────────────────────────────────

  const handleLpSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLpStatus("loading");
    setLpError("");
    try {
      const mxePub = await getMxePubkey();
      const { encrypted, iv, clientPublicKey } = await encryptOfferFields(
        { capital: parseFloat(lpCapital), minYield: parseFloat(lpMinYield) },
        mxePub
      );
      const res = await fetch("/api/offer/lp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          id: lpId,
          encryptedCapital: encrypted.capital,
          encryptedMinYield: encrypted.minYield,
          iv,
          clientPublicKey,
        }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(JSON.stringify(err));
      }
      setLpStatus("success");
    } catch (err) {
      setLpStatus("error");
      setLpError(String(err));
    }
  };

  // ── Protocol submit ────────────────────────────────────────────────────────

  const handleProtocolSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setProtocolStatus("loading");
    setProtocolError("");
    try {
      const mxePub = await getMxePubkey();
      const { encrypted, iv, clientPublicKey } = await encryptOfferFields(
        { demand: parseFloat(protocolDemand), maxRate: parseFloat(protocolMaxRate) },
        mxePub
      );
      const res = await fetch("/api/offer/protocol", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          id: protocolId,
          encryptedDemand: encrypted.demand,
          encryptedMaxRate: encrypted.maxRate,
          iv,
          clientPublicKey,
        }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(JSON.stringify(err));
      }
      setProtocolStatus("success");
    } catch (err) {
      setProtocolStatus("error");
      setProtocolError(String(err));
    }
  };

  // ── Settlement ─────────────────────────────────────────────────────────────

  const handleSettle = async () => {
    setSettleStatus("loading");
    setSettleError("");
    try {
      const res = await fetch("/api/settle", { method: "POST" });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error ?? JSON.stringify(err));
      }
      setSettlementResult(await res.json());
      setSettleStatus("success");
    } catch (err) {
      setSettleStatus("error");
      setSettleError(String(err));
    }
  };

  // ── Check result ───────────────────────────────────────────────────────────

  const handleCheckResult = async (e: React.FormEvent) => {
    e.preventDefault();
    setCheckStatus("loading");
    setCheckError("");
    setCheckResult(null);
    try {
      const res = await fetch(`/api/result/${encodeURIComponent(checkId.trim())}`);
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error ?? JSON.stringify(err));
      }
      setCheckResult(await res.json());
      setCheckStatus("success");
    } catch (err) {
      setCheckStatus("error");
      setCheckError(String(err));
    }
  };

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div
      className="min-h-screen text-white"
      style={{
        background: "linear-gradient(140deg, #000000 0%, #020617 35%, #070720 65%, #000000 100%)",
        fontFamily: "var(--font-geist-sans), sans-serif",
      }}
    >
      {/* ── Banner ── */}
      <div
        className="w-full text-center py-2 px-4 text-[11px] font-mono tracking-[0.15em]"
        style={{
          background:
            "linear-gradient(90deg, rgba(6,182,212,0.07) 0%, rgba(168,85,247,0.07) 100%)",
          borderBottom: "1px solid rgba(6,182,212,0.18)",
          color: "#67e8f9",
        }}
      >
        ⚡ MXE Simulated — Arcium encrypted compute environment
      </div>

      <main className="mx-auto max-w-lg px-4 py-14">
        {/* ── Header ── */}
        <div className="text-center mb-11">
          <div
            className="inline-block text-[10px] font-semibold px-3 py-1 rounded-full mb-4 tracking-[0.2em]"
            style={{
              background: "rgba(168,85,247,0.1)",
              border: "1px solid rgba(168,85,247,0.28)",
              color: "#c084fc",
            }}
          >
            PRIVATE YIELD OPTIMIZER
          </div>

          <h1
            className="text-4xl sm:text-5xl font-bold tracking-tight mb-3 leading-tight"
            style={{
              background:
                "linear-gradient(135deg, #ffffff 0%, #22d3ee 45%, #a855f7 100%)",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
            }}
          >
            Sealed Auction
          </h1>

          <p className="text-slate-500 text-sm leading-relaxed">
            Capital allocated via encrypted bidding · Matching runs inside the MXE
          </p>
        </div>

        {/* ── Mode switcher ── */}
        <div
          className="flex rounded-2xl p-1 mb-8"
          style={{
            background: "rgba(255,255,255,0.03)",
            border: "1px solid rgba(255,255,255,0.07)",
          }}
        >
          {(["lp", "protocol", "auctioneer"] as Mode[]).map((m) => {
            const label = { lp: "LP Mode", protocol: "Protocol Mode", auctioneer: "Auctioneer" }[m];
            const active = mode === m;
            return (
              <button
                key={m}
                onClick={() => setMode(m)}
                className="flex-1 py-2.5 px-2 rounded-xl text-xs sm:text-sm font-medium transition-all duration-200 truncate"
                style={
                  active
                    ? {
                        background:
                          "linear-gradient(135deg, rgba(6,182,212,0.14) 0%, rgba(168,85,247,0.14) 100%)",
                        border: "1px solid rgba(6,182,212,0.32)",
                        color: "#67e8f9",
                        boxShadow: "0 0 18px rgba(6,182,212,0.12)",
                      }
                    : { color: "#64748b" }
                }
              >
                {label}
              </button>
            );
          })}
        </div>

        {/* ════════════════════════════════════════════════
            LP MODE
        ════════════════════════════════════════════════ */}
        {mode === "lp" && (
          <div style={card}>
            {/* Card header */}
            <div className="flex items-center gap-3 mb-7">
              <div
                className="w-10 h-10 rounded-xl flex items-center justify-center text-xl shrink-0"
                style={{
                  background: "rgba(6,182,212,0.12)",
                  border: "1px solid rgba(6,182,212,0.28)",
                }}
              >
                💰
              </div>
              <div>
                <h2 className="text-base font-semibold text-white">LP Offer</h2>
                <p className="text-xs text-slate-600">Submit capital with encrypted yield floor</p>
              </div>
            </div>

            {lpStatus !== "success" ? (
              <form onSubmit={handleLpSubmit} className="flex flex-col gap-4">
                <Field
                  label="Capital Amount (USD)"
                  type="number"
                  min="0"
                  step="any"
                  placeholder="e.g. 100000"
                  value={lpCapital}
                  onChange={(e) => setLpCapital(e.target.value)}
                  accent="cyan"
                  required
                />
                <Field
                  label="Minimum Yield Floor (%)"
                  type="number"
                  min="0"
                  step="any"
                  placeholder="e.g. 4.5"
                  value={lpMinYield}
                  onChange={(e) => setLpMinYield(e.target.value)}
                  accent="cyan"
                  required
                />
                <IdField value={lpId} onChange={setLpId} accent="cyan" />

                {lpStatus === "error" && <ErrorBox msg={lpError} />}

                <button
                  type="submit"
                  disabled={lpStatus === "loading"}
                  className="btn-glow-cyan mt-1 w-full rounded-xl py-3.5 text-sm font-semibold text-white transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
                  style={{
                    background: "linear-gradient(135deg, #0891b2 0%, #6d28d9 100%)",
                  }}
                >
                  {lpStatus === "loading" ? (
                    <span className="flex items-center justify-center gap-2">
                      <Spinner /> Encrypting &amp; Submitting…
                    </span>
                  ) : (
                    "Submit LP Offer"
                  )}
                </button>
                <EncryptBadge />
              </form>
            ) : (
              <SuccessCard
                participantId={lpId}
                color="cyan"
                onReset={() => {
                  setLpStatus("idle");
                  setLpCapital("");
                  setLpMinYield("");
                  setLpId(crypto.randomUUID());
                }}
              />
            )}
          </div>
        )}

        {/* ════════════════════════════════════════════════
            PROTOCOL MODE
        ════════════════════════════════════════════════ */}
        {mode === "protocol" && (
          <div style={card}>
            <div className="flex items-center gap-3 mb-7">
              <div
                className="w-10 h-10 rounded-xl flex items-center justify-center text-xl shrink-0"
                style={{
                  background: "rgba(168,85,247,0.12)",
                  border: "1px solid rgba(168,85,247,0.28)",
                }}
              >
                🏦
              </div>
              <div>
                <h2 className="text-base font-semibold text-white">Protocol Offer</h2>
                <p className="text-xs text-slate-600">Submit liquidity demand with encrypted rate ceiling</p>
              </div>
            </div>

            {protocolStatus !== "success" ? (
              <form onSubmit={handleProtocolSubmit} className="flex flex-col gap-4">
                <Field
                  label="Liquidity Demand (USD)"
                  type="number"
                  min="0"
                  step="any"
                  placeholder="e.g. 50000"
                  value={protocolDemand}
                  onChange={(e) => setProtocolDemand(e.target.value)}
                  accent="purple"
                  required
                />
                <Field
                  label="Maximum Rate Ceiling (%)"
                  type="number"
                  min="0"
                  step="any"
                  placeholder="e.g. 8.0"
                  value={protocolMaxRate}
                  onChange={(e) => setProtocolMaxRate(e.target.value)}
                  accent="purple"
                  required
                />
                <IdField value={protocolId} onChange={setProtocolId} accent="purple" />

                {protocolStatus === "error" && <ErrorBox msg={protocolError} />}

                <button
                  type="submit"
                  disabled={protocolStatus === "loading"}
                  className="mt-1 w-full rounded-xl py-3.5 text-sm font-semibold text-white transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
                  style={{
                    background: "linear-gradient(135deg, #6d28d9 0%, #0891b2 100%)",
                    boxShadow: "0 4px 22px rgba(168,85,247,0.22)",
                  }}
                >
                  {protocolStatus === "loading" ? (
                    <span className="flex items-center justify-center gap-2">
                      <Spinner /> Encrypting &amp; Submitting…
                    </span>
                  ) : (
                    "Submit Protocol Offer"
                  )}
                </button>
                <EncryptBadge />
              </form>
            ) : (
              <SuccessCard
                participantId={protocolId}
                color="purple"
                onReset={() => {
                  setProtocolStatus("idle");
                  setProtocolDemand("");
                  setProtocolMaxRate("");
                  setProtocolId(crypto.randomUUID());
                }}
              />
            )}
          </div>
        )}

        {/* ════════════════════════════════════════════════
            AUCTIONEER MODE
        ════════════════════════════════════════════════ */}
        {mode === "auctioneer" && (
          <div className="flex flex-col gap-4">
            {/* Trigger settlement */}
            <div style={card}>
              <div className="flex items-center gap-3 mb-7">
                <div
                  className="w-10 h-10 rounded-xl flex items-center justify-center text-xl shrink-0"
                  style={{
                    background: "rgba(251,191,36,0.1)",
                    border: "1px solid rgba(251,191,36,0.22)",
                  }}
                >
                  ⚡
                </div>
                <div>
                  <h2 className="text-base font-semibold text-white">Trigger Settlement</h2>
                  <p className="text-xs text-slate-600">
                    Runs the sealed double auction inside the MXE
                  </p>
                </div>
              </div>

              <button
                onClick={handleSettle}
                disabled={settleStatus === "loading"}
                className="w-full rounded-xl py-3.5 text-sm font-semibold text-white transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
                style={{
                  background: "linear-gradient(135deg, #b45309 0%, #c2410c 100%)",
                  boxShadow: "0 4px 22px rgba(234,88,12,0.2)",
                }}
              >
                {settleStatus === "loading" ? (
                  <span className="flex items-center justify-center gap-2">
                    <Spinner /> Running Auction…
                  </span>
                ) : (
                  "Trigger Settlement"
                )}
              </button>

              {settleStatus === "error" && (
                <div className="mt-3">
                  <ErrorBox msg={settleError} />
                </div>
              )}

              {settleStatus === "success" && settlementResult && (
                <div className="mt-5">
                  <div
                    className="rounded-xl p-4"
                    style={{
                      background: "rgba(16,185,129,0.06)",
                      border: "1px solid rgba(16,185,129,0.2)",
                    }}
                  >
                    <p className="text-emerald-400 text-sm font-semibold mb-4 flex items-center gap-2">
                      <span>✅</span> Settlement Complete
                    </p>
                    <div className="grid grid-cols-2 gap-2 mb-3">
                      <StatBox
                        label="Capital Matched"
                        value={`$${settlementResult.totalCapitalMatched.toLocaleString()}`}
                        accent="cyan"
                      />
                      <StatBox
                        label="Avg Clearing Rate"
                        value={`${settlementResult.averageClearingRate.toFixed(4)}%`}
                        accent="cyan"
                      />
                      <StatBox
                        label="Participants"
                        value={String(settlementResult.participantCount)}
                        accent="purple"
                      />
                      <StatBox
                        label="Matches"
                        value={String(settlementResult.matches.length)}
                        accent="purple"
                      />
                    </div>

                    {/* Algorithm hash */}
                    <div
                      className="rounded-xl px-4 py-3 flex items-start gap-2.5"
                      style={{
                        background: "rgba(255,255,255,0.025)",
                        border: "1px solid rgba(255,255,255,0.06)",
                      }}
                    >
                      <span className="text-base mt-0.5">🔏</span>
                      <div className="min-w-0">
                        <p className="text-[10px] text-slate-500 uppercase tracking-[0.15em] mb-1">
                          Algorithm Hash
                        </p>
                        <p className="text-[11px] font-mono text-slate-400 break-all">
                          {settlementResult.algorithmHash.slice(0, 40)}…
                        </p>
                      </div>
                    </div>

                    <p className="text-[10px] text-slate-600 mt-2.5 text-right">
                      {new Date(settlementResult.settledAt).toLocaleString()}
                    </p>
                  </div>
                </div>
              )}
            </div>

            {/* Check my result */}
            <div style={card}>
              <div className="flex items-center gap-3 mb-7">
                <div
                  className="w-10 h-10 rounded-xl flex items-center justify-center text-xl shrink-0"
                  style={{
                    background: "rgba(6,182,212,0.1)",
                    border: "1px solid rgba(6,182,212,0.25)",
                  }}
                >
                  🔍
                </div>
                <div>
                  <h2 className="text-base font-semibold text-white">Check My Result</h2>
                  <p className="text-xs text-slate-600">
                    Only your matched pairs are revealed — nothing else
                  </p>
                </div>
              </div>

              <form onSubmit={handleCheckResult} className="flex flex-col gap-4">
                <div className="flex flex-col gap-1.5">
                  <label className={labelCls}>Participant ID</label>
                  <input
                    value={checkId}
                    onChange={(e) => setCheckId(e.target.value)}
                    className={inputCls}
                    placeholder="Paste your participant UUID…"
                    required
                  />
                </div>

                <button
                  type="submit"
                  disabled={checkStatus === "loading"}
                  className="w-full rounded-xl py-3.5 text-sm font-semibold text-white transition-all duration-200 disabled:opacity-50"
                  style={{
                    background: "linear-gradient(135deg, #0891b2 0%, #6d28d9 100%)",
                    boxShadow: "0 4px 22px rgba(6,182,212,0.18)",
                  }}
                >
                  {checkStatus === "loading" ? (
                    <span className="flex items-center justify-center gap-2">
                      <Spinner /> Fetching…
                    </span>
                  ) : (
                    "Check Result"
                  )}
                </button>

                {checkStatus === "error" && <ErrorBox msg={checkError} />}

                {checkStatus === "success" && checkResult && (
                  <div className="flex flex-col gap-2 mt-1">
                    {checkResult.matches.length === 0 ? (
                      <p className="text-sm text-slate-500 text-center py-4">
                        No matches found for this participant.
                      </p>
                    ) : (
                      checkResult.matches.map((m, i) => (
                        <div
                          key={i}
                          className="rounded-xl p-4"
                          style={{
                            background: "rgba(6,182,212,0.055)",
                            border: "1px solid rgba(6,182,212,0.18)",
                          }}
                        >
                          <div className="flex items-center justify-between mb-3">
                            <span className="text-[10px] text-cyan-500 font-semibold uppercase tracking-widest">
                              Match #{i + 1}
                            </span>
                            <span
                              className="text-[11px] font-mono px-2.5 py-1 rounded-full"
                              style={{
                                background: "rgba(6,182,212,0.14)",
                                border: "1px solid rgba(6,182,212,0.3)",
                                color: "#67e8f9",
                              }}
                            >
                              {m.clearingRate.toFixed(4)}% clearing
                            </span>
                          </div>

                          <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
                            <div>
                              <p className="text-slate-600 mb-0.5 text-[10px] uppercase tracking-widest">
                                LP
                              </p>
                              <p className="font-mono text-slate-400 truncate">
                                {m.lpId.slice(0, 18)}…
                              </p>
                            </div>
                            <div>
                              <p className="text-slate-600 mb-0.5 text-[10px] uppercase tracking-widest">
                                Protocol
                              </p>
                              <p className="font-mono text-slate-400 truncate">
                                {m.protocolId.slice(0, 18)}…
                              </p>
                            </div>
                            <div>
                              <p className="text-slate-600 mb-0.5 text-[10px] uppercase tracking-widest">
                                Capital Allocated
                              </p>
                              <p className="font-semibold text-white">
                                ${m.capitalAllocated.toLocaleString()}
                              </p>
                            </div>
                            <div>
                              <p className="text-slate-600 mb-0.5 text-[10px] uppercase tracking-widest">
                                Clearing Rate
                              </p>
                              <p className="font-semibold text-cyan-400">{m.clearingRate.toFixed(4)}%</p>
                            </div>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                )}
              </form>
            </div>
          </div>
        )}

        {/* ── Footer ── */}
        <p className="text-center text-[11px] text-slate-700 mt-12 leading-relaxed">
          Offers encrypted client-side · Matching computed inside MXE
          <br />
          Results selectively revealed — bids never leave your browser in plaintext
        </p>
      </main>
    </div>
  );
}
