/**
 * Singleton store for attack recommendation state that persists across route changes.
 *
 * Follows the same pattern as remediation-store.ts:
 * - Lives outside React — the SSE stream runs even when the component is unmounted.
 * - Writes every state change to sessionStorage.
 * - React components subscribe via onChange().
 */

import { ai as aiApi, ApiError } from "./api";

// ── Types ──────────────────────────────────────────────────────────

export interface AttackRecommendationState {
  selectedScanId: string;
  recommendation: string;
  model: string;
  generatedAt: string;
  generating: boolean;
  reviewAction: string;
  lastError: string;
}

type Listener = (state: AttackRecommendationState) => void;

// ── Constants ──────────────────────────────────────────────────────

const STORAGE_KEY = "ashen_attack_recommendation_state";

// ── Persistence ────────────────────────────────────────────────────

function loadFromStorage(): Partial<AttackRecommendationState> {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
}

function saveToStorage(s: AttackRecommendationState) {
  try {
    const { generating: _, lastError: __, ...persisted } = s;
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(persisted));
  } catch {
    // non-critical
  }
}

// ── Store singleton ────────────────────────────────────────────────

function createStore() {
  const saved = loadFromStorage();

  let state: AttackRecommendationState = {
    selectedScanId: saved.selectedScanId ?? "",
    recommendation: saved.recommendation ?? "",
    model: saved.model ?? "",
    generatedAt: saved.generatedAt ?? "",
    generating: false,
    reviewAction: saved.reviewAction ?? "",
    lastError: "",
  };

  const listeners = new Set<Listener>();

  function emit() {
    saveToStorage(state);
    listeners.forEach((fn) => fn(state));
  }

  function update(patch: Partial<AttackRecommendationState>) {
    state = { ...state, ...patch };
    emit();
  }

  return {
    getState(): AttackRecommendationState {
      return state;
    },

    onChange(fn: Listener): () => void {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },

    setSelectedScanId(id: string) {
      update({ selectedScanId: id });
    },

    /** Start recommendation generation — runs in background, survives unmount. */
    async generate() {
      if (!state.selectedScanId) {
        update({ lastError: "Select a scan first." });
        return;
      }

      update({
        generating: true,
        recommendation: "",
        reviewAction: "",
        model: "",
        generatedAt: new Date().toISOString(),
        lastError: "",
      });

      try {
        const full = await aiApi.recommendAttacksStream(
          { scan_id: Number(state.selectedScanId) },
          (token) => {
            state = { ...state, recommendation: state.recommendation + token };
            emit();
          },
          (model) => update({ model }),
        );
        update({ recommendation: full, generating: false });
      } catch (e) {
        const msg =
          e instanceof ApiError
            ? e.message
            : "AI service unavailable. Check that Ollama is running and try again.";
        update({ generating: false, lastError: msg });
      }
    },

    async review(action: "accept" | "reject" | "regenerate") {
      try {
        const res = await aiApi.review(action, Number(state.selectedScanId));
        update({ reviewAction: action });

        if (action === "regenerate") {
          this.generate();
        }
      } catch (e) {
        const msg = e instanceof ApiError ? e.message : "Review failed";
        update({ lastError: msg });
      }
    },
  };
}

export const attackRecommendationStore = createStore();
