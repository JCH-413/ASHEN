/**
 * Singleton store for remediation state that persists across route changes.
 *
 * - Lives outside React — the SSE stream runs even when the component is unmounted.
 * - Writes every state change to sessionStorage so it survives full page refreshes.
 * - React components subscribe/unsubscribe via onChange(); the store doesn't care
 *   whether anyone is listening.
 */

import { ai as aiApi, ApiError } from "./api";

// ── Types ──────────────────────────────────────────────────────────

export interface ChatMessage {
  role: "user" | "ai";
  content: string;
}

export interface RemediationState {
  selectedVulnId: string;
  selectedExploitId: string;
  guidance: string;
  model: string;
  generatedAt: string;
  generating: boolean;
  reviewAction: string;
  chatMessages: ChatMessage[];
  chatLoading: boolean;
  lastError: string;
}

type Listener = (state: RemediationState) => void;

// ── Constants ──────────────────────────────────────────────────────

const STORAGE_KEY = "ashen_remediation_state";

const DEFAULT_GREETING: ChatMessage = {
  role: "ai",
  content:
    "Hello! I'm your AI remediation assistant. Select a vulnerability or exploit above, then ask me anything.",
};

// ── Persistence ────────────────────────────────────────────────────

function loadFromStorage(): Partial<RemediationState> {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
}

function saveToStorage(s: RemediationState) {
  try {
    // Don't persist transient flags — they'll be derived on reload
    const { generating: _, chatLoading: __, lastError: ___, ...persisted } = s;
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(persisted));
  } catch {
    // non-critical
  }
}

// ── Store singleton ────────────────────────────────────────────────

function createStore() {
  const saved = loadFromStorage();

  let state: RemediationState = {
    selectedVulnId: saved.selectedVulnId ?? "",
    selectedExploitId: saved.selectedExploitId ?? "",
    guidance: saved.guidance ?? "",
    model: saved.model ?? "",
    generatedAt: saved.generatedAt ?? "",
    generating: false,
    reviewAction: saved.reviewAction ?? "",
    chatMessages: saved.chatMessages?.length ? saved.chatMessages : [DEFAULT_GREETING],
    chatLoading: false,
    lastError: "",
  };

  const listeners = new Set<Listener>();

  function emit() {
    saveToStorage(state);
    listeners.forEach((fn) => fn(state));
  }

  function update(patch: Partial<RemediationState>) {
    state = { ...state, ...patch };
    emit();
  }

  // ── Public API ─────────────────────────────────────────────────

  return {
    /** Get current snapshot (no subscription). */
    getState(): RemediationState {
      return state;
    },

    /** Subscribe to changes. Returns unsubscribe function. */
    onChange(fn: Listener): () => void {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },

    setSelectedVulnId(id: string) {
      update({ selectedVulnId: id });
    },

    setSelectedExploitId(id: string) {
      update({ selectedExploitId: id });
    },

    setChatInput(_v: string) {
      // chatInput is local to the component — we don't persist keystrokes
    },

    /** Start remediation generation — runs in background, survives unmount. */
    async generate() {
      if (!state.selectedVulnId && !state.selectedExploitId) {
        update({ lastError: "Select a vulnerability or exploit first." });
        return;
      }

      update({
        generating: true,
        guidance: "",
        reviewAction: "",
        model: "tinyllama",
        generatedAt: new Date().toISOString(),
        lastError: "",
      });

      try {
        const full = await aiApi.remediateStream(
          {
            vuln_id: state.selectedVulnId ? Number(state.selectedVulnId) : undefined,
            exploit_id: state.selectedExploitId ? Number(state.selectedExploitId) : undefined,
          },
          (token) => {
            state = { ...state, guidance: state.guidance + token };
            emit();
          },
        );
        update({ guidance: full, generating: false });
      } catch (e) {
        const msg =
          e instanceof ApiError
            ? e.message
            : "AI service unavailable. Check that Ollama is running and try again.";
        update({ generating: false, lastError: msg });
      }
    },

    /** Submit a review action. */
    async review(action: "accept" | "reject" | "regenerate") {
      try {
        await aiApi.review(action);
        update({ reviewAction: action });
        if (action === "regenerate") {
          this.generate();
        }
      } catch (e) {
        const msg = e instanceof ApiError ? e.message : "Review failed";
        update({ lastError: msg });
      }
    },

    /** Send a chat message — streams response in background. */
    async sendChat(question: string) {
      if (!question.trim()) return;

      // Push user message + empty AI placeholder
      const withUser: ChatMessage[] = [
        ...state.chatMessages,
        { role: "user", content: question },
        { role: "ai", content: "" },
      ];
      update({ chatMessages: withUser, chatLoading: true, lastError: "" });

      try {
        const full = await aiApi.chatStream(
          {
            question,
            vuln_id: state.selectedVulnId ? Number(state.selectedVulnId) : undefined,
            exploit_id: state.selectedExploitId ? Number(state.selectedExploitId) : undefined,
            remediation_context: state.guidance || undefined,
          },
          (token) => {
            // Append token to the last AI message
            const msgs = [...state.chatMessages];
            const last = msgs[msgs.length - 1];
            if (last && last.role === "ai") {
              msgs[msgs.length - 1] = { ...last, content: last.content + token };
            }
            state = { ...state, chatMessages: msgs };
            emit();
          },
        );

        // Finalize
        const msgs = [...state.chatMessages];
        const last = msgs[msgs.length - 1];
        if (last && last.role === "ai") {
          msgs[msgs.length - 1] = { ...last, content: full };
        }
        update({ chatMessages: msgs, chatLoading: false });
      } catch {
        const msgs = [...state.chatMessages];
        const last = msgs[msgs.length - 1];
        if (last && last.role === "ai") {
          msgs[msgs.length - 1] = {
            ...last,
            content: "AI service unavailable. Please check that Ollama is running and try again.",
          };
        }
        update({ chatMessages: msgs, chatLoading: false });
      }
    },
  };
}

/** The single global instance — imported by any component that needs it. */
export const remediationStore = createStore();
