"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Check,
  Copy,
  Eye,
  EyeOff,
  KeyRound,
  Loader2,
  Lock,
  LogOut,
  Plus,
  RefreshCcw,
  Search,
  ShieldCheck,
  Sparkles,
  Trash2,
} from "lucide-react";
import { decryptVaultData, encryptVaultData, type VaultCipher } from "@/lib/crypto";

type Phase = "checking" | "setup" | "unlock" | "ready";
type StatusKind = "success" | "error" | "info";

interface VaultEntry {
  id: string;
  service: string;
  username: string;
  password: string;
  url?: string;
  notes?: string;
  createdAt: string;
  updatedAt: string;
}

interface VaultBlob {
  entries: VaultEntry[];
}

interface StatusBanner {
  kind: StatusKind;
  message: string;
}

const STORAGE_KEY = "cipherSafe.vault";
const CLIPBOARD_MS = 1800;

const initialFormState = {
  service: "",
  username: "",
  password: "",
  url: "",
  notes: "",
};

const passwordChecks = [
  { test: (value: string) => value.length >= 12, score: 1 },
  { test: (value: string) => value.length >= 16, score: 1 },
  { test: (value: string) => /[a-z]/.test(value) && /[A-Z]/.test(value), score: 1 },
  { test: (value: string) => /\d/.test(value), score: 1 },
  { test: (value: string) => /[^A-Za-z0-9]/.test(value), score: 1 },
];

function evaluateStrength(password: string) {
  if (!password) {
    return { label: "", width: "0%", tone: "bg-transparent" };
  }
  const score = passwordChecks.reduce(
    (total, rule) => (rule.test(password) ? total + rule.score : total),
    0,
  );
  const width = `${Math.min((score / passwordChecks.length) * 100, 100)}%`;
  let label: string;
  let tone: string;
  if (score >= 4) {
    label = "Strong";
    tone = "bg-success";
  } else if (score >= 3) {
    label = "Good";
    tone = "bg-accent";
  } else {
    label = "Weak";
    tone = "bg-danger";
  }
  return { label, width, tone };
}

function generatePassword(length = 20) {
  const lower = "abcdefghijkmnopqrstuvwxyz";
  const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
  const digits = "23456789";
  const symbols = "!@#$%^&*()-_=+[]{}<>?";
  const all = lower + upper + digits + symbols;
  const result: string[] = [];

  const ensure = [lower, upper, digits, symbols];
  ensure.forEach((set) => {
    result.push(set[Math.floor(Math.random() * set.length)]);
  });

  const randomByte = () => {
    if (typeof crypto !== "undefined" && crypto.getRandomValues) {
      const buffer = new Uint8Array(1);
      crypto.getRandomValues(buffer);
      return buffer[0];
    }
    return Math.floor(Math.random() * 256);
  };

  while (result.length < length) {
    const index = randomByte() % all.length;
    result.push(all[index]);
  }

  return result
    .sort(() => (randomByte() % 2 === 0 ? 1 : -1))
    .join("")
    .slice(0, length);
}

function formatTimestamp(value: string) {
  return new Intl.DateTimeFormat("en", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

function getStoredCipher(): VaultCipher | null {
  if (typeof window === "undefined") return null;
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as VaultCipher;
  } catch {
    return null;
  }
}

function createVaultId() {
  if (typeof crypto !== "undefined") {
    if (crypto.randomUUID) {
      return crypto.randomUUID();
    }
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  }
  return `vault-${Math.random().toString(36).slice(2, 10)}`;
}

export default function Home() {
  const [phase, setPhase] = useState<Phase>("checking");
  const [entries, setEntries] = useState<VaultEntry[]>([]);
  const [form, setForm] = useState(initialFormState);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [masterPassword, setMasterPassword] = useState("");
  const [setupPassword, setSetupPassword] = useState({ password: "", confirm: "" });
  const [unlockPassword, setUnlockPassword] = useState("");
  const [status, setStatus] = useState<StatusBanner | null>(null);
  const [revealedEntryId, setRevealedEntryId] = useState<string | null>(null);
  const [copiedEntryId, setCopiedEntryId] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [isProcessing, setIsProcessing] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }
    const cipher = getStoredCipher();
    if (cipher) {
      setPhase("unlock");
      setLastUpdated(cipher.updatedAt ?? null);
    } else {
      setPhase("setup");
    }
  }, []);

  useEffect(() => {
    if (!status) return;
    const timer = setTimeout(() => setStatus(null), 4500);
    return () => clearTimeout(timer);
  }, [status]);

  useEffect(() => {
    if (!copiedEntryId) return;
    const timer = setTimeout(() => setCopiedEntryId(null), CLIPBOARD_MS);
    return () => clearTimeout(timer);
  }, [copiedEntryId]);

  const filteredEntries = useMemo(() => {
    if (!searchTerm.trim()) return entries;
    const term = searchTerm.toLowerCase();
    return entries.filter((entry) => {
      return (
        entry.service.toLowerCase().includes(term) ||
        entry.username.toLowerCase().includes(term) ||
        entry.url?.toLowerCase().includes(term)
      );
    });
  }, [entries, searchTerm]);

  const persistVault = useCallback(
    async (nextEntries: VaultEntry[], successMessage?: string) => {
      if (!masterPassword) {
        setStatus({
          kind: "error",
          message: "Master password missing. Please unlock your vault again.",
        });
        setPhase("unlock");
        setEntries([]);
        return;
      }
      try {
        setIsSaving(true);
        const cipher = await encryptVaultData(masterPassword, { entries: nextEntries });
        localStorage.setItem(STORAGE_KEY, JSON.stringify(cipher));
        setEntries(nextEntries);
        setLastUpdated(cipher.updatedAt ?? new Date().toISOString());
        if (successMessage) {
          setStatus({ kind: "success", message: successMessage });
        }
      } catch (error) {
        console.error(error);
        setStatus({
          kind: "error",
          message: "Unable to save vault. Please try again.",
        });
      } finally {
        setIsSaving(false);
      }
    },
    [masterPassword],
  );

  const handleSetupVault = async () => {
    if (setupPassword.password.length < 12) {
      setStatus({
        kind: "error",
        message: "Choose a master password of at least 12 characters.",
      });
      return;
    }
    if (setupPassword.password !== setupPassword.confirm) {
      setStatus({
        kind: "error",
        message: "Password confirmation does not match.",
      });
      return;
    }
    try {
      setIsProcessing(true);
      const cipher = await encryptVaultData(setupPassword.password, { entries: [] });
      localStorage.setItem(STORAGE_KEY, JSON.stringify(cipher));
      setMasterPassword(setupPassword.password);
      setEntries([]);
      setLastUpdated(cipher.updatedAt ?? null);
      setPhase("ready");
      setSetupPassword({ password: "", confirm: "" });
      setStatus({
        kind: "success",
        message: "Vault created. Add your first credential securely.",
      });
    } catch (error) {
      console.error(error);
      setStatus({
        kind: "error",
        message: "Failed to create vault. Please ensure Web Crypto is available.",
      });
    } finally {
      setIsProcessing(false);
    }
  };

  const handleUnlockVault = async () => {
    const cipher = getStoredCipher();
    if (!cipher) {
      setStatus({
        kind: "error",
        message: "No vault found. Create a new one to get started.",
      });
      setPhase("setup");
      return;
    }
    try {
      setIsProcessing(true);
      const decrypted = await decryptVaultData(unlockPassword, cipher);
      const parsed = JSON.parse(decrypted) as VaultBlob;
      const vaultEntries = Array.isArray(parsed.entries) ? parsed.entries : [];
      setEntries(vaultEntries);
      setMasterPassword(unlockPassword);
      setUnlockPassword("");
      setPhase("ready");
      setLastUpdated(cipher.updatedAt ?? null);
      setStatus({ kind: "success", message: "Vault unlocked. Stay vigilant." });
    } catch (error) {
      console.error(error);
      setStatus({
        kind: "error",
        message: "Incorrect master password. Access denied.",
      });
    } finally {
      setIsProcessing(false);
    }
  };

  const handleAddOrUpdateEntry = async () => {
    if (!form.service.trim() || !form.username.trim() || !form.password.trim()) {
      setStatus({
        kind: "error",
        message: "Service, username, and password are required.",
      });
      return;
    }
    const timestamp = new Date().toISOString();
    if (editingId) {
      const nextEntries = entries.map((entry) =>
        entry.id === editingId
          ? { ...entry, ...form, updatedAt: timestamp }
          : entry,
      );
      await persistVault(nextEntries, "Entry updated.");
    } else {
      const nextEntries = [
        {
          id: createVaultId(),
          service: form.service.trim(),
          username: form.username.trim(),
          password: form.password.trim(),
          url: form.url?.trim() || "",
          notes: form.notes?.trim() || "",
          createdAt: timestamp,
          updatedAt: timestamp,
        },
        ...entries,
      ];
      await persistVault(nextEntries, "New credential secured.");
    }
    setForm(initialFormState);
    setEditingId(null);
  };

  const handleDeleteEntry = async (id: string) => {
    const entry = entries.find((item) => item.id === id);
    if (!entry) return;
    const confirmed = window.confirm(
      `Delete credential for "${entry.service}"? This cannot be undone.`,
    );
    if (!confirmed) return;
    const nextEntries = entries.filter((item) => item.id !== id);
    await persistVault(nextEntries, "Entry removed.");
    if (editingId === id) {
      setEditingId(null);
      setForm(initialFormState);
    }
  };

  const handleLockVault = () => {
    setMasterPassword("");
    setEntries([]);
    setPhase("unlock");
    setStatus({ kind: "info", message: "Vault locked. Stay sharp." });
  };

  const handleResetVault = () => {
    const confirmed = window.confirm(
      "This will destroy your encrypted vault file on this device. Proceed?",
    );
    if (!confirmed) return;
    localStorage.removeItem(STORAGE_KEY);
    setMasterPassword("");
    setEntries([]);
    setPhase("setup");
    setLastUpdated(null);
    setStatus({
      kind: "info",
      message: "Vault cleared from this browser. Create a new master password.",
    });
  };

  const handleCopy = async (value: string, id: string) => {
    if (typeof navigator === "undefined" || !navigator.clipboard) {
      setStatus({
        kind: "error",
        message: "Clipboard API unavailable in this browser.",
      });
      return;
    }
    try {
      await navigator.clipboard.writeText(value);
      setCopiedEntryId(id);
      setStatus({ kind: "success", message: "Copied to clipboard." });
    } catch (error) {
      console.error(error);
      setStatus({
        kind: "error",
        message: "Clipboard permissions denied.",
      });
    }
  };

  const stats = useMemo(() => {
    const usernames = new Set(entries.map((entry) => entry.username));
    const domains = new Set(
      entries
        .map((entry) => {
          try {
            return entry.url ? new URL(entry.url).hostname : null;
          } catch {
            return null;
          }
        })
        .filter(Boolean) as string[],
    );
    return {
      total: entries.length,
      identities: usernames.size,
      domains: domains.size,
    };
  }, [entries]);

  const strength = evaluateStrength(form.password);

  const renderStatusBanner = () => {
    if (!status) return null;
    const palette = {
      success: "border-success/40 bg-success/10 text-success",
      error: "border-danger/40 bg-danger/10 text-danger",
      info: "border-accent/30 bg-accent/10 text-accent",
    } as const;
    return (
      <div
        className={`animate-in fade-in slide-in-from-top-2 fixed left-1/2 top-6 z-50 w-full max-w-xl -translate-x-1/2 rounded-2xl border px-4 py-3 text-sm font-medium shadow-lg backdrop-blur ${
          palette[status.kind]
        }`}
      >
        {status.message}
      </div>
    );
  };

  const renderSetup = () => (
    <div className="mx-auto flex w-full max-w-lg flex-col gap-6 rounded-3xl border border-border/40 bg-surface/60 p-10 text-foreground shadow-[0_0_60px_rgba(5,255,180,0.14)] backdrop-blur">
      <div className="flex items-center gap-3 text-2xl font-semibold">
        <ShieldCheck className="h-8 w-8 text-accent" />
        <span>Initialize CipherSafe</span>
      </div>
      <p className="text-sm text-muted">
        Your data never leaves this device. Pick a master password you will remember; it
        cannot be recovered if lost. The vault uses AES-GCM with a PBKDF2-derived key.
      </p>
      <label className="flex flex-col gap-2 text-sm">
        <span className="text-muted">Master password</span>
        <input
          type="password"
          className="rounded-2xl border border-border/40 bg-background/70 px-4 py-3 text-sm outline-none transition focus:border-accent focus:shadow-[0_0_0_2px_rgba(159,239,0,0.25)]"
          value={setupPassword.password}
          onChange={(event) =>
            setSetupPassword((prev) => ({ ...prev, password: event.target.value }))
          }
          placeholder="Minimum 12 characters"
        />
      </label>
      <label className="flex flex-col gap-2 text-sm">
        <span className="text-muted">Confirm master password</span>
        <input
          type="password"
          className="rounded-2xl border border-border/40 bg-background/70 px-4 py-3 text-sm outline-none transition focus:border-accent focus:shadow-[0_0_0_2px_rgba(159,239,0,0.25)]"
          value={setupPassword.confirm}
          onChange={(event) =>
            setSetupPassword((prev) => ({ ...prev, confirm: event.target.value }))
          }
          placeholder="Retype to verify"
        />
      </label>
      <button
        onClick={handleSetupVault}
        disabled={isProcessing}
        className="group inline-flex items-center justify-center gap-2 rounded-2xl bg-accent px-4 py-3 text-sm font-semibold text-background transition hover:bg-accent-strong disabled:cursor-not-allowed disabled:opacity-60"
      >
        {isProcessing ? (
          <>
            <Loader2 className="h-4 w-4 animate-spin" />
            Securing vault…
          </>
        ) : (
          <>
            <Sparkles className="h-4 w-4 transition group-hover:rotate-12" />
            Create vault
          </>
        )}
      </button>
    </div>
  );

  const renderUnlock = () => (
    <div className="mx-auto flex w-full max-w-lg flex-col gap-6 rounded-3xl border border-border/40 bg-surface/60 p-10 text-foreground shadow-[0_0_60px_rgba(5,255,180,0.14)] backdrop-blur">
      <div className="flex items-center gap-3 text-2xl font-semibold">
        <Lock className="h-8 w-8 text-accent" />
        <span>Unlock CipherSafe</span>
      </div>
      <p className="text-sm text-muted">
        Enter the master password you created on this device. CipherSafe does not transmit
        or sync data; everything stays local and encrypted.
      </p>
      <label className="flex flex-col gap-2 text-sm">
        <span className="text-muted">Master password</span>
        <input
          type="password"
          className="rounded-2xl border border-border/40 bg-background/70 px-4 py-3 text-sm outline-none transition focus:border-accent focus:shadow-[0_0_0_2px_rgba(159,239,0,0.25)]"
          value={unlockPassword}
          onChange={(event) => setUnlockPassword(event.target.value)}
          placeholder="Enter master password"
        />
      </label>
      <button
        onClick={handleUnlockVault}
        disabled={isProcessing}
        className="group inline-flex items-center justify-center gap-2 rounded-2xl bg-accent px-4 py-3 text-sm font-semibold text-background transition hover:bg-accent-strong disabled:cursor-not-allowed disabled:opacity-60"
      >
        {isProcessing ? (
          <>
            <Loader2 className="h-4 w-4 animate-spin" />
            Verifying…
          </>
        ) : (
          <>
            <ShieldCheck className="h-4 w-4 transition group-hover:scale-110" />
            Unlock vault
          </>
        )}
      </button>
      <button
        onClick={handleResetVault}
        className="text-xs text-muted underline-offset-4 transition hover:text-accent hover:underline"
      >
        Reset this device&apos;s vault
      </button>
    </div>
  );

  const renderShimmer = () => (
    <div className="flex min-h-screen flex-col items-center justify-center gap-4">
      <Loader2 className="h-8 w-8 animate-spin text-accent" />
      <p className="text-sm text-muted">Booting up your secure workspace…</p>
    </div>
  );

  const renderVaultInterface = () => (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-8 pb-16">
      <div className="rounded-3xl border border-border/40 bg-surface/60 p-8 shadow-[0_0_80px_rgba(5,255,180,0.1)] backdrop-blur">
        <div className="flex flex-col gap-6 md:flex-row md:items-start md:justify-between">
          <div className="flex flex-col gap-2">
            <div className="flex items-center gap-2 text-xs uppercase tracking-widest text-accent">
              <span className="inline-flex h-7 w-7 items-center justify-center rounded-full border border-accent/30 bg-background/70">
                <ShieldCheck className="h-4 w-4" />
              </span>
              <span>CipherSafe Vault</span>
            </div>
            <h1 className="text-3xl font-semibold text-foreground md:text-4xl">
              Precision-grade credential management
            </h1>
            <p className="max-w-2xl text-sm text-muted">
              Your secrets live encrypted with AES-256-GCM and never touch a network. Add
              credentials, generate hardened passwords, and audit your digital footprint —
              all inside a zero-trust interface inspired by Hack The Box.
            </p>
          </div>
          <div className="flex flex-col items-start gap-3 rounded-2xl border border-border/40 bg-background/40 p-4 text-xs text-muted">
            <div className="flex items-center gap-2 text-sm font-semibold text-foreground">
              <KeyRound className="h-4 w-4 text-accent" />
              Session active
            </div>
            <p>Entries: <span className="text-foreground">{stats.total}</span></p>
            <p>Identities: <span className="text-foreground">{stats.identities}</span></p>
            <p>Domains: <span className="text-foreground">{stats.domains}</span></p>
            {lastUpdated && (
              <p className="text-[11px] text-muted">
                Updated {formatTimestamp(lastUpdated)}
              </p>
            )}
            <button
              onClick={handleLockVault}
              className="inline-flex items-center gap-2 rounded-xl border border-accent/30 px-3 py-2 text-[11px] font-semibold text-accent transition hover:bg-accent/20"
            >
              <LogOut className="h-3.5 w-3.5" />
              Lock vault
            </button>
          </div>
        </div>
      </div>

      <div className="flex flex-col gap-6 rounded-3xl border border-border/40 bg-surface/60 p-8 backdrop-blur">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:gap-6">
            <div className="flex w-full flex-col gap-2 lg:w-80">
              <label className="text-xs uppercase tracking-widest text-muted">
                Search vault
              </label>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
                <input
                  value={searchTerm}
                  onChange={(event) => setSearchTerm(event.target.value)}
                  placeholder="Service, username, or domain"
                  className="w-full rounded-2xl border border-border/40 bg-background/70 py-3 pl-9 pr-4 text-sm outline-none transition focus:border-accent focus:shadow-[0_0_0_2px_rgba(159,239,0,0.25)]"
                />
              </div>
            </div>
            <button
              onClick={() => {
                setForm(initialFormState);
                setEditingId(null);
                setSearchTerm("");
              }}
              className="inline-flex items-center justify-center gap-2 rounded-2xl border border-border/40 bg-background/40 px-4 py-3 text-sm font-semibold text-foreground transition hover:border-accent/40 hover:bg-surface-hover"
            >
              <RefreshCcw className="h-4 w-4" />
              Reset filters
            </button>
          </div>
          <button
            onClick={() => {
              setForm({ ...initialFormState, password: generatePassword(20) });
              setEditingId(null);
            }}
            className="group inline-flex items-center justify-center gap-2 rounded-2xl bg-accent px-4 py-3 text-sm font-semibold text-background transition hover:bg-accent-strong"
          >
            <Plus className="h-4 w-4 transition-all group-hover:rotate-90" />
            New credential
          </button>
        </div>

        <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
          <div className="flex flex-col gap-5 rounded-3xl border border-border/40 bg-background/50 p-6">
            <div className="flex items-center justify-between">
              <span className="text-sm font-semibold text-foreground">
                {editingId ? "Edit credential" : "Add credential"}
              </span>
              {editingId && (
                <button
                  onClick={() => {
                    setEditingId(null);
                    setForm(initialFormState);
                  }}
                  className="text-xs text-muted underline-offset-4 transition hover:text-accent hover:underline"
                >
                  Cancel edit
                </button>
              )}
            </div>
            <div className="grid gap-4">
              <label className="flex flex-col gap-2 text-xs text-muted">
                Service / label
                <input
                  value={form.service}
                  onChange={(event) =>
                    setForm((prev) => ({ ...prev, service: event.target.value }))
                  }
                  placeholder="Vault access, staging console, etc."
                  className="rounded-2xl border border-border/40 bg-surface/60 px-4 py-3 text-sm text-foreground outline-none transition focus:border-accent focus:shadow-[0_0_0_2px_rgba(159,239,0,0.25)]"
                />
              </label>
              <label className="flex flex-col gap-2 text-xs text-muted">
                Username / email
                <input
                  value={form.username}
                  onChange={(event) =>
                    setForm((prev) => ({ ...prev, username: event.target.value }))
                  }
                  placeholder="jane@operator.htb"
                  className="rounded-2xl border border-border/40 bg-surface/60 px-4 py-3 text-sm text-foreground outline-none transition focus:border-accent focus:shadow-[0_0_0_2px_rgba(159,239,0,0.25)]"
                />
              </label>
              <div className="flex flex-col gap-2 text-xs text-muted">
                <span>Password</span>
                <div className="flex items-center gap-2">
                  <input
                    value={form.password}
                    onChange={(event) =>
                      setForm((prev) => ({ ...prev, password: event.target.value }))
                    }
                    placeholder="Strong, unique password"
                    className="flex-1 rounded-2xl border border-border/40 bg-surface/60 px-4 py-3 text-sm text-foreground outline-none transition focus:border-accent focus:shadow-[0_0_0_2px_rgba(159,239,0,0.25)]"
                  />
                  <button
                    onClick={() =>
                      setForm((prev) => ({ ...prev, password: generatePassword(24) }))
                    }
                    type="button"
                    className="inline-flex items-center justify-center gap-2 rounded-2xl border border-border/40 bg-background/40 px-4 py-3 text-xs font-semibold text-foreground transition hover:border-accent/40 hover:bg-surface-hover"
                  >
                    <Sparkles className="h-4 w-4" />
                    Generate
                  </button>
                </div>
                {strength.label && (
                  <div className="flex flex-col gap-1 text-[11px] text-muted">
                    <div className="h-1.5 w-full rounded-full bg-background/60">
                      <div
                        className={`h-full rounded-full ${strength.tone}`}
                        style={{ width: strength.width }}
                      />
                    </div>
                    <span className="text-xs text-foreground">{strength.label} password</span>
                  </div>
                )}
              </div>
              <label className="flex flex-col gap-2 text-xs text-muted">
                URL (optional)
                <input
                  value={form.url}
                  onChange={(event) =>
                    setForm((prev) => ({ ...prev, url: event.target.value }))
                  }
                  placeholder="https://"
                  className="rounded-2xl border border-border/40 bg-surface/60 px-4 py-3 text-sm text-foreground outline-none transition focus:border-accent focus:shadow-[0_0_0_2px_rgba(159,239,0,0.25)]"
                />
              </label>
              <label className="flex flex-col gap-2 text-xs text-muted">
                Notes (optional)
                <textarea
                  value={form.notes}
                  onChange={(event) =>
                    setForm((prev) => ({ ...prev, notes: event.target.value }))
                  }
                  rows={3}
                  placeholder="MFA tokens, onboarding secrets, recovery codes…"
                  className="rounded-2xl border border-border/40 bg-surface/60 px-4 py-3 text-sm text-foreground outline-none transition focus:border-accent focus:shadow-[0_0_0_2px_rgba(159,239,0,0.25)]"
                />
              </label>
            </div>
            <button
              onClick={handleAddOrUpdateEntry}
              disabled={isSaving}
              className="group inline-flex items-center justify-center gap-2 rounded-2xl bg-accent px-4 py-3 text-sm font-semibold text-background transition hover:bg-accent-strong disabled:cursor-not-allowed disabled:opacity-60"
            >
              {isSaving ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Securing entry…
                </>
              ) : (
                <>
                  <Check className="h-4 w-4 transition group-hover:scale-110" />
                  {editingId ? "Update credential" : "Store credential"}
                </>
              )}
            </button>
          </div>

          <div className="flex flex-col gap-4">
            <div className="flex items-center justify-between">
              <span className="text-sm font-semibold text-foreground">Vault inventory</span>
              <span className="text-xs text-muted">{filteredEntries.length} visible</span>
            </div>
            <div className="grid gap-4">
              {filteredEntries.length === 0 && (
                <div className="flex flex-col items-center justify-center gap-3 rounded-3xl border border-dashed border-border/40 bg-background/50 p-10 text-muted">
                  <ShieldCheck className="h-8 w-8 text-accent" />
                  <p className="text-sm text-center text-muted">
                    No credentials match your search. Create a new entry or reset filters.
                  </p>
                </div>
              )}
              {filteredEntries.map((entry) => {
                const isRevealed = revealedEntryId === entry.id;
                const isCopied = copiedEntryId === entry.id;
                return (
                  <div
                    key={entry.id}
                    className="group flex flex-col gap-4 rounded-3xl border border-border/40 bg-background/50 p-5 transition hover:border-accent/40 hover:bg-surface/70"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="flex items-center gap-2 text-sm font-semibold text-foreground">
                          <span className="inline-flex h-8 w-8 items-center justify-center rounded-xl border border-accent/20 bg-accent/10 text-accent">
                            {entry.service.charAt(0).toUpperCase()}
                          </span>
                          {entry.service}
                        </div>
                        <p className="mt-1 text-xs text-muted">{entry.username}</p>
                      </div>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => handleCopy(entry.password, entry.id)}
                          className="inline-flex h-9 w-9 items-center justify-center rounded-xl border border-border/40 text-sm text-muted transition hover:border-accent/40 hover:text-accent"
                        >
                          {isCopied ? (
                            <Check className="h-4 w-4" />
                          ) : (
                            <Copy className="h-4 w-4" />
                          )}
                        </button>
                        <button
                          onClick={() =>
                            setRevealedEntryId(isRevealed ? null : entry.id)
                          }
                          className="inline-flex h-9 w-9 items-center justify-center rounded-xl border border-border/40 text-sm text-muted transition hover:border-accent/40 hover:text-accent"
                        >
                          {isRevealed ? (
                            <EyeOff className="h-4 w-4" />
                          ) : (
                            <Eye className="h-4 w-4" />
                          )}
                        </button>
                      </div>
                    </div>
                    <div className="flex flex-col gap-3 text-xs text-muted">
                      <div className="flex gap-2">
                        <span className="rounded-full bg-background/60 px-3 py-1 font-mono text-[11px] text-foreground">
                          {isRevealed ? entry.password : "••••••••••••••"}
                        </span>
                      </div>
                      {entry.url && (
                        <a
                          href={entry.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-xs text-accent underline-offset-4 transition hover:underline"
                        >
                          {entry.url}
                        </a>
                      )}
                      {entry.notes && (
                        <p className="rounded-2xl border border-border/30 bg-background/50 p-3 text-[12px] leading-relaxed text-foreground/80">
                          {entry.notes}
                        </p>
                      )}
                    </div>
                    <div className="flex flex-wrap items-center justify-between gap-3 text-[11px] text-muted">
                      <span>Updated {formatTimestamp(entry.updatedAt)}</span>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => {
                            setEditingId(entry.id);
                            setForm({
                              service: entry.service,
                              username: entry.username,
                              password: entry.password,
                              url: entry.url ?? "",
                              notes: entry.notes ?? "",
                            });
                          }}
                          className="text-xs text-muted underline-offset-4 transition hover:text-accent hover:underline"
                        >
                          Edit
                        </button>
                        <button
                          onClick={() => handleDeleteEntry(entry.id)}
                          className="inline-flex items-center gap-1 rounded-xl border border-danger/30 px-3 py-1.5 text-[11px] text-danger transition hover:bg-danger/10"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                          Delete
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  return (
    <div className="relative min-h-screen px-4 py-12 sm:px-6 lg:px-12">
      {renderStatusBanner()}
      <div className="pointer-events-none absolute inset-x-0 top-0 flex justify-center pt-10">
        <div className="h-32 w-32 rounded-full bg-accent/20 blur-3xl" />
      </div>
      {phase === "checking" && renderShimmer()}
      {phase === "setup" && renderSetup()}
      {phase === "unlock" && renderUnlock()}
      {phase === "ready" && renderVaultInterface()}
    </div>
  );
}
