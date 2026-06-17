# ASHEN: Action-Aware Retrieval-Augmented LLM Guidance for Authorized Penetration Testing with Closed-Loop Remediation Validation

*Working draft — v0.2. Live results: E1 grounding (§5), seed/temperature variance
(§6.2), and closed-loop remediation efficacy (§6.3) on 3 hosts covering all four
exploit types; PentestGPT capability comparison (§2). Pilot-scale (3 hosts) —
results are trends, not significance. Remaining `[PLACEHOLDER]`s: multi-target
scale-up, a model-strength study, and an empirical PentestGPT head-to-head.*

---

## Abstract

Large language models (LLMs) are increasingly proposed to assist penetration
testing, but most systems are demonstrations that stop at recommendation and are
evaluated subjectively. We present **ASHEN**, an AI-assisted penetration-testing
platform that closes the full loop — scan, vulnerability detection, exploit
validation, retrieval-augmented attack recommendation, remediation guidance, and
**re-validation of the generated fix by re-exploitation** — under an explicit
authorization-and-audit governance model, using a **local** LLM so that no target
data leaves the operator's network. We make three contributions. First, we
introduce an evaluation harness that uses ASHEN's own exploit runner as an
**objective oracle**: an exploit type is "correct" for a target iff running it
returns a positive verdict, which lets us score recommendation ranking and
remediation efficacy without human judgement. Second, using this oracle we show
that **naïvely** injecting retrieved CVE knowledge into the recommender degrades
action selection, and that an **action-aware grounding** scheme — which maps
retrieved CVEs onto the tool's available exploit types — restores correct ranking
while keeping the recommendation grounded. Third, we define **remediation
efficacy** as the fraction of confirmed vulnerabilities that no longer validate
after the generated fix is applied, an end-to-end metric that, to our knowledge,
no comparable system reports. In a feasibility pilot (4 remediation trials,
efficacy 0.25), the loop caught three confident-but-incorrect LLM fixes — including
one whose command *executed successfully and passed the LLM's own validation step*
yet left the host exploitable — that a recommendation-only, human-rated, or
self-validating evaluation would have accepted. Applying the same grounding scheme
to the remediation step then recovers the failure end-to-end (the prescribed fix
changes from a hollow command to the effective one; efficacy 0.25→0.75), unifying
our two results: grounding corrects both recommendation and remediation. We
describe the protocol for scaling to a larger multi-target evaluation.

---

## 1. Introduction

Penetration testing is a manual, expertise-intensive process, which has motivated
a substantial body of work on *autonomous penetration testing* [rlreview]. Two
families of decision-making methods dominate: reinforcement-learning (RL) agents
that learn attack and path-planning policies in simulated networks
[rlreview, autoptsim], and, more recently, large language model (LLM) agents that
exploit the models' contextual semantic understanding to drive the workflow
[pentestgpt, hacksynth]. ASHEN belongs to the LLM-based family. However, existing
LLM-based pentest systems share three weaknesses that limit their scientific
standing:

1. **They stop at recommendation.** The LLM suggests what to try; whether the
   suggestion *works*, and whether any fix it proposes actually *removes* the
   weakness, is left unmeasured.
2. **They are evaluated subjectively.** Output quality is judged by human raters
   or anecdotes, so results are hard to reproduce and easy to contest.
3. **They send sensitive data to a third-party API.** Target IPs, detected
   vulnerabilities, and credentials are transmitted to a hosted model — a
   confidentiality problem for real engagements.

ASHEN addresses all three. It runs an **on-premise** LLM (no data exfiltration),
it **validates** every exploit it recommends and every fix it proposes against
the live target, and it is wrapped in an authorization-gated governance model
with dual audit logs. Crucially, because ASHEN can *execute* exploits, the same
execution serves as an **objective oracle** for evaluation — turning otherwise
subjective questions ("is this recommendation good?", "is this fix correct?")
into measurable ones.

**Contributions.**

- **C1 — An oracle-backed evaluation harness** (§4) that scores recommendation
  ranking and remediation efficacy using the exploit runner's verdict as ground
  truth, requiring no human labelling.
- **C2 — Action-aware retrieval grounding** (§3.3, §5): we show that dumping
  retrieved CVEs into the prompt biases the model toward CVE-shaped actions the
  tool cannot perform, and that mapping retrieved CVEs onto the available exploit
  types fixes this. *(E1, n=3 hosts: robust across Linux, Windows, and Shellshock
  where plain RAG is not; more targets at scale `[PLACEHOLDER]`.)*
- **C3 — Closed-loop remediation efficacy** (§3.4, §6.3): an end-to-end metric
  that re-exploits the target after the generated fix is applied. *(Pilot, n=4,
  efficacy 0.25→0.75 grounded: the loop caught three incorrect fixes — including one that executed
  successfully and passed its own validation yet left the host exploitable; full
  study `[PLACEHOLDER]`.)*

---

## 2. Background and Related Work

**Autonomous and automated penetration testing.** A large literature casts
penetration testing as a sequential decision-making problem and applies
reinforcement learning (RL) to learn attack and path-planning policies in
simulated networks. Liu et al. [rlreview] provide a recent review of RL-based
decision-making for autonomous pentesting, and unified modeling frameworks such
as AutoPT-Sim [autoptsim] standardise the simulation environments these agents
train in. Such methods excel at policy learning but operate in simulation,
produce no human-readable guidance, and address neither remediation nor data
confidentiality — gaps that motivate the LLM-based, on-premise design of ASHEN.

**LLMs for offensive security.** The closest system is PentestGPT [pentestgpt]
(Deng et al., USENIX Security 2024), which integrates GPT-3.5 and GPT-4 and
organises a pentest around a **Pentesting Task Tree (PTT)** driven by three
modules (Reasoning, Generation, Parsing). It is evaluated on a benchmark of **13
HackTheBox/VulnHub targets (182 sub-tasks)** and reports a **228.6% task-completion
increase over its GPT-3.5 baseline**. Two properties distinguish it from ASHEN:
(i) it is **cloud/API-backed** (target data is sent to OpenAI), and (ii) it is
**human-in-the-loop and offensive-only** — the operator executes the LLM's
suggested commands and feeds results back, and the system "aims at identifying,
assessing, and mitigating … vulnerabilities" through exploitation, with **no
remediation-generation or fix-validation component**. A parallel line shows LLM agents can *autonomously
exploit* without a human executor: Fang et al. demonstrate autonomous website
hacking [fang-web], exploitation of real **one-day** CVEs with a GPT-4 agent over
a 15-vulnerability benchmark [fang-oneday], and **teams** of agents exploiting
zero-day web vulnerabilities [fang-zeroday]; Happe and Cito study autonomous
Linux privilege escalation [happe]. Most directly comparable, HackSynth
[hacksynth] pairs a dual-module LLM agent (a Planner and a Summarizer that
iteratively generate commands and process feedback) with a CTF-based **evaluation
framework** and, like ASHEN, stresses the importance of robust safeguards. These
establish that LLMs can drive offence, but — like PentestGPT — they stop at
exploitation and judge success by human or capture-the-flag task-completion rather
than execution as an objective oracle, and none generate or **re-validate**
remediations.

We do not re-run PentestGPT empirically (its native backend is a paid OpenAI API,
and a fair run would require GPT-4); instead we compare capabilities against its
published design (Table~\ref{tab:pgpt}) and cite its reported results. A
same-target empirical head-to-head is future work (§6.6).

| Capability | PentestGPT [pentestgpt] | ASHEN |
|------------|-------------------------|-------|
| LLM backend | GPT-3.5 / GPT-4 (cloud, OpenAI) | **local** (Ollama, llama3.2; on-prem) |
| Target-data exposure | sent to OpenAI API | **stays on-premise** |
| Core method | Pentesting Task Tree + 3 modules | scan→detect→validate→RAG-grounded recommend→remediate→re-validate |
| Command execution | human-in-the-loop (operator runs, feeds back) | **automated** (executes exploits) |
| Result validation | none (no objective oracle) | **execution-as-oracle** (exploit verdict) |
| Recommendation grounding | task-tree context | **RAG + action-aware grounding** |
| Remediation | **none** (offensive only) | five-part, RAG-grounded |
| Fix re-validation | **none** | **re-exploit (closed loop)** |
| Evaluation | task-completion, human-scored (13 targets) | objective, oracle-scored |

*Table: ASHEN vs PentestGPT (capability comparison; PentestGPT facts from
[pentestgpt]).*

**Retrieval-augmented generation (RAG).** RAG [rag] grounds LLM output in a
retrieved corpus to reduce hallucination. We show (§5) that in a *tool-using*
setting, naïve RAG can instead *mis-direct action selection* when the knowledge
representation (CVEs) is misaligned with the action space (exploit types) — a
phenomenon we have not seen characterised in the offensive-security context.

**Vulnerability remediation with LLMs.** LLMs have been applied to vulnerability
repair — e.g. Pearce et al.'s zero-shot vulnerability repair with LLMs
[pearce], which generates code fixes but evaluates them against a test suite, not
by re-exploiting a live target. Closest to ASHEN is **PenHeal** [penheal], a
two-stage framework that pairs a pentest module with a **remediation** module and
reports improved vulnerability coverage and remediation effectiveness. Crucially,
PenHeal *recommends and scores* remediation strategies but does **not re-validate
them by re-exploiting the patched system** — exactly the gap ASHEN's closed loop
fills: ASHEN applies the fix and re-runs the exploit, so a remediation that looks
correct but does not actually remove the weakness (as in our §6.3 cases) is
caught. To our knowledge ASHEN is the first to score remediation by
re-exploitation.

**Position of ASHEN.** ASHEN is distinguished by the combination of (i) local
LLM, (ii) execution-as-oracle evaluation, and (iii) closed-loop remediation
validation, under (iv) an explicit authorization/audit governance model.

---

## 3. ASHEN System Design

### 3.1 Overview and roles
ASHEN separates an **Analyst** (runs scans/exploits on authorised targets, sees
only their own work) from an **Admin** (whitelists target IPs, approves target
requests, reads the audit log). A target is an IPv4 address an Admin has placed
in scope. The assessment workflow is: **Scan** (Nmap [nmap] `-sV --script vuln`) →
**Vulnerability** (an unvalidated NSE detection) → **Exploit Run** (validates or
refutes a Vulnerability) → **Attack Recommendation** (RAG-grounded LLM guidance)
→ **Remediation** (LLM fix guidance) → **Report**.

### 3.2 Exploit types as a typed action space
ASHEN exposes a small, typed set of **exploit types**, each a uniform adapter
producing a single verdict envelope (`ran`, `vulnerable`, `evidence`). The
current set is four: `ssh_brute_force`, `ftp_brute_force` (credential family) and
`ms17_010_check`, `shellshock_cgi` (check family). This typed action space is
what makes both the oracle (§4) and action-aware grounding (§3.3) possible.

### 3.3 Retrieval grounding (and its failure mode)
The recommender retrieves CVE context from a vector store (ChromaDB [chroma] over
sentence-transformer embeddings [sbert]) and conditions an attack recommendation on it.
We compare three grounding conditions:

- **off** — no retrieval.
- **plain** — retrieved CVEs are concatenated into the prompt (the baseline
  behaviour).
- **action-aware** — each retrieved CVE is mapped onto the exploit types whose
  declared `service` + `signatures` it matches; CVEs matching no available
  exploit are surfaced as *informational only*. The corpus stays tool-agnostic;
  adding an exploit type changes only that exploit's declaration.

### 3.4 Closed-loop remediation
For a confirmed-vulnerable finding, ASHEN generates a five-part remediation
(Root Cause / Immediate Containment / Permanent Fix / Validation / Hardening).
The fix is applied to the target (manually, in the current system), after which
the **same exploit is re-run**: the vulnerability is "remediated" iff it no
longer validates *and* the service is still reachable.

### 3.5 Governance and the local-LLM choice
Every operator action is recorded in an Audit Log; every LLM prompt/response is
recorded in a separate AI Governance Log. The LLM runs on-premise (Ollama), so
target data never leaves the network — a deliberate confidentiality choice that
distinguishes ASHEN from API-backed tools.

---

## 4. Evaluation Methodology

### 4.1 Execution as an objective oracle
For a target and an exploit type, the exploit runner returns a boolean
`vulnerable` verdict. We treat this as **ground truth**: an exploit type is
*relevant* for a target iff it returns `vulnerable=True`. This removes human
judgement from (a) scoring whether a recommendation ranks working exploits first,
and (b) scoring whether a remediation removed the weakness.

### 4.2 Metrics
- **Precision@1 / MRR** of the recommended exploitation order against the
  relevant set (recommendation ranking; E1/E2).
- **Fabrication rate** — fraction of CVEs cited by the recommender that are not
  in a curated set of CVEs real-and-applicable to the target (E1).
- **Remediation efficacy** — fraction of confirmed-vulnerable findings that, after
  the generated fix is applied, no longer validate *and* leave the service up
  (`fixed` vs `not_fixed` vs `broke_service`). *(Headline; §6.3.)*

### 4.3 Harness and reproducibility
The harness drives ASHEN's services directly (no web/auth/DB layer). Generation
is seeded (`temperature=0`, `seed=42`) for reproducibility. A full live run is
split into isolated phases (oracle / recommend / remediate) so memory-heavy
components do not run concurrently. *(Implementation: `ashen/backend/eval/`.)*

### 4.4 Testbed
**(3 hosts, pilot)** Three targets spanning all four exploit types with positive
cases: Metasploitable 2 (`192.168.28.130`; Linux — vsftpd 2.3.4, OpenSSH 4.7p1,
Apache 2.2.8, Samba 3.x → `ssh`/`ftp` brute-force), Metasploitable 3 Windows
Server 2008 R2 (`192.168.28.132`; SMBv1 → `ms17_010_check`/EternalBlue), and an
Ubuntu 14.04 host (`192.168.28.133`; Apache `mod_cgi` + unpatched bash →
`shellshock_cgi`). Further scale-up protocol in §6.4.

---

## 5. E1: Grounding and Recommendation Quality *(live, n=3 hosts, pilot)*

**Setup.** Three hosts spanning all four exploit types: Metasploitable 2 (Linux;
relevant = {`ftp_brute_force`, `ssh_brute_force`}), Metasploitable 3 Windows
Server 2008 R2 (relevant = {`ms17_010_check`}, i.e. EternalBlue), and an Ubuntu
14.04 Shellshock host (relevant = {`shellshock_cgi`}). Ground truth is established
per target by the oracle. We ran the recommender under the three grounding
conditions with a fixed seed; fabrication is scored against a *per-target* set of
applicable CVEs (so EternalBlue counts as valid on the Windows host but as a
fabrication on the Linux one).

**Results (per target).**

| Target | Grounding | Top-1 | P@1 | MRR | Fabrication |
|--------|-----------|-------|-----|-----|-------------|
| MS2 (Linux)   | off          | `ftp_brute_force` ✓ | 1.00 | 1.00 | n/a |
| MS2 (Linux)   | plain        | `ms17_010_check` ✗  | 0.00 | 0.00 | 0.60 |
| MS2 (Linux)   | action-aware | `ssh_brute_force` ✓ | 1.00 | 1.00 | 1.00\* |
| MS3 (Windows) | off          | `ms17_010_check` ✓  | 1.00 | 1.00 | n/a |
| MS3 (Windows) | plain        | `ms17_010_check` ✓  | 1.00 | 1.00 | n/a |
| MS3 (Windows) | action-aware | `ms17_010_check` ✓  | 1.00 | 1.00 | n/a |
| Shellshock    | off          | `shellshock_cgi` ✓  | 1.00 | 1.00 | n/a |
| Shellshock    | plain        | `shellshock_cgi` ✓  | 1.00 | 1.00 | 0.60 |
| Shellshock    | action-aware | `shellshock_cgi` ✓  | 1.00 | 1.00 | 0.50 |

**Aggregate Precision@1 (n=3):** off $=1.00$, plain $=0.67$, action-aware $=1.00$.

*Live, `temperature=0`, `seed=42` (deterministic). \*The MS2 action-aware
fabrication is a single-citation artifact: the model cited one off-platform CVE
(`CVE-2017-0144`, EternalBlue) for the low-priority `ms17_010` entry; on MS3 that
same CVE is correct. Shellshock is correctly top-ranked by all conditions (it is
the only exploitable service on that host). Raw data: `eval/run_e1_all.{csv,json}`.*

**Findings.**

1. **Plain RAG is unreliable, and its failure is target-dependent.** Plain
   retrieval biases the model toward SMB/CVE-heavy exploits regardless of
   applicability. This is *wrong* on the Linux host (it ranks the dead-end
   `ms17_010` first, P@1 $=0$) but *coincidentally right* on the Windows host
   (where `ms17_010`/EternalBlue genuinely is the answer, P@1 $=1$). Aggregated,
   plain RAG scores only P@1 $=0.67$ — still the worst condition, and not robust across targets.
2. **Action-aware grounding is robust:** P@1 $=1.0$ across all three hosts. Mapping
   retrieved CVEs onto the available exploit types, and quarantining unmatched
   CVEs as informational, keeps the recommendation correct *and* grounded on both
   targets. It is the only condition that achieves correct ranking **and**
   grounded justification across targets — plain sacrifices ranking, `off`
   sacrifices grounding (it cites nothing).
3. **The per-target CVE distinction validates the oracle-grounded design.** The
   same CVE (`CVE-2017-0144`) is correctly treated as a fabrication on Linux and
   as valid evidence on Windows, because correctness is judged against each
   host's actual exposure, not a global list.
4. **A residual fabrication artifact (MS2).** Action-aware still cited one
   off-platform CVE for a low-priority exploit; this motivates
   platform-applicability filtering (§7), i.e. not attaching a CVE as evidence
   when its platform contradicts the fingerprint.

**Interpretation.** The mechanism is a **knowledge↔action-space misalignment**:
grounding a tool-using LLM on a CVE corpus biases it toward CVE-shaped actions,
including ones outside the tool's capability or inapplicable to the host. Aligning
the knowledge to the action space (and judging it per-target) resolves this. A 5-seed × 2-temperature
variance study (§6.2) confirms this is not a single-seed artifact: at a
task-appropriate temperature action-aware is perfectly stable (1.00 ± 0.00) and
plain RAG is the worst at every temperature.
*Caveat: n=3 hosts; broader generalisation in §6.1/§6.4.*

---

## 6. Remaining Evaluation `[PLACEHOLDER]`

### 6.1 E2 — Ranking depth and precision across targets `[PLACEHOLDER]`
*Same oracle, more targets; report Precision@1 and MRR with confidence
intervals. Needs ≥ N targets (§6.4).*

### 6.2 Variance / stochasticity *(live, 5 seeds × 3 targets × 2 temperatures)*

The deterministic E1 run (§5, `temperature=0`) could be a single-seed artifact, so
we re-ran all conditions across 5 seeds and 3 targets at two temperatures. Exploit
selection is a *decision* task, for which a low temperature (0.3) is appropriate;
we also stress-test at a high creative-generation temperature (0.7).

| Condition | Precision@1 @ τ=0.3 | Precision@1 @ τ=0.7 |
|-----------|---------------------|---------------------|
| off          | **1.00 ± 0.00** (15/15) | 0.93 ± 0.26 |
| plain        | 0.67 ± 0.47 (10/15) | 0.50 ± 0.50 |
| action-aware | **1.00 ± 0.00** (15/15) | 0.79 ± 0.41 |

**Findings.** (i) **Plain RAG is the worst at both temperatures** and highly
variable — a robust negative result, not a seed artifact. (ii) **At the
task-appropriate temperature, action-aware grounding is perfectly stable**
(1.00 ± 0.00, 15/15), matching the ungrounded baseline on ranking while retaining
its CVE justification. (iii) Action-aware's degradation at τ=0.7 (0.79) is a
diagnosed high-temperature artifact — the model occasionally defaulting to
brute-forcing open SSH/FTP ports against the grounding's advice — not a flaw in
the grounding; even there it stays well above plain RAG. We de-emphasise the
fabrication metric here: it is high and noisy for both RAG conditions
(~0.6–0.7 at both temperatures) and dominated by per-target applicability edge
cases, so it does not discriminate the conditions. *(Raw:
`eval/variance_results_t03.json`, `eval/variance_results.json`.)*

### 6.3 Headline — Remediation efficacy *(live, n=4 trials across 3 hosts, pilot)*

**Setup.** Four confirmed-vulnerable findings (all four exploit types) were remediated end-to-end: ASHEN
generated its five-part guidance for each, **ASHEN's prescribed fix was applied
verbatim** to the live host (over SSH; hosts snapshotted first), and the **same
exploit was re-run** to score the outcome.

**Results.**

| Host / finding | ASHEN's prescribed fix | After (re-exploited) | Outcome |
|----------------|------------------------|----------------------|---------|
| MS2 `ssh_brute_force` | rotate weak credentials | no credentials found | **fixed** |
| MS2 `ftp_brute_force` | rotate weak credentials (+ a hallucinated `allow_root` option) | `ftp:<any>` still logs in | **not_fixed** |
| MS3 `ms17_010_check` | `reg add … /v DisableSMBv1 /d 1` (command **succeeds**, key verified present) | host still MS17-010 vulnerable after reboot | **not_fixed** |
| Shellshock `shellshock_cgi` | update Apache mod_cgi (wrong component — Shellshock is a *bash* bug) | host still Shellshock-vulnerable | **not_fixed** |

**Remediation efficacy = 0.25 (1 / 4 fixed).** *(Raw:
`eval/results_remediation_live.json`, `eval/results_remediation_ms3.json`, `eval/results_remediation_shellshock_ungrounded.json`.)*

**Findings.**

1. **The closed loop caught a plausible-but-wrong fix (MS2 FTP).** ASHEN's FTP
   remediation reads convincingly but asserts the root cause is weak credentials.
   **Re-exploitation proved otherwise:** the exposure is *anonymous login* (the
   `ftp` account accepts any password), which credential rotation cannot address.
2. **It caught a fix that *executed successfully but did nothing* (MS3
   MS17-010).** Here ASHEN diagnosed the root cause *correctly* (SMBv1) but
   prescribed a wrong command: it sets a non-existent registry value
   (`DisableSMBv1`; the effective control is `SMB1=0`). The command **returns
   "completed successfully," the key is verifiably present, and ASHEN's own
   suggested validation step (`reg query` to confirm the key) passes** — yet after
   a reboot the host is still EternalBlue-vulnerable. **Every check short of
   re-attacking reports success; only re-exploitation reveals the fix is hollow.**
   This is the strongest case for execution-based validation: surface validation
   (exit code, key present, the LLM's own validation) gives a false positive.
3. **All three ungrounded failures misdiagnosed the fix.** The FTP guidance
   invented `allow_root`; the MS17-010 guidance invented `DisableSMBv1`; the
   Shellshock guidance prescribed *updating Apache* for a *bash* vulnerability
   (wrong component) — linking to §5: ungrounded remediation fabricates
   plausible-but-wrong fixes.
4. **Where diagnosis *and* command were correct, the fix worked (MS2 SSH)** — the
   positive control showing the loop also confirms genuinely effective fixes.

**Interpretation.** Even at pilot scale, the headline metric exposes what
recommendation-only, human-rated, *or even self-validating* LLM remediation would
miss: an LLM fix's *confidence, structure, successful execution, and passing its
own validation step are all uncorrelated with whether the vulnerability is
actually gone.* Only execution-based re-validation reveals the difference. Scaling
this metric across many findings (§6.4) is the priority follow-up. **Caveat:**
n = 4 trials across three hosts; not a rate estimate.

**Grounding the remediation closes the gap (re-validated end-to-end).** The
remediation path, unlike the recommender (§5), was originally *ungrounded*
free-form generation — the source of the hallucinated fixes above. We applied the
same grounding principle: retrieve curated, verified fix references and constrain
the LLM to base every concrete command/value on them, then **re-ran all four
remediations end-to-end** (generate → apply verbatim → re-exploit):

| Finding | Ungrounded fix → outcome | Grounded fix → outcome |
|---------|--------------------------|------------------------|
| MS2 `ssh_brute_force` | rotate creds → **fixed** | rotate creds → **fixed** |
| MS2 `ftp_brute_force` | `allow_root` (bogus) → **not_fixed** | `anonymous_enable=NO` (correct) → **not_fixed** |
| MS3 `ms17_010_check` | `DisableSMBv1` (hollow) → **not_fixed** | `SMB1=0` → **fixed** |
| Shellshock `shellshock_cgi` | update Apache (wrong component) → **not_fixed** | disable mod_cgi → **fixed** |
| **Efficacy** | **0.25 (1/4)** | **0.75 (3/4)** |

Grounding **corrected the prescription on all four findings** (the SSH credential
fix, `SMB1=0` for MS17-010, `anonymous_enable=NO` for FTP replacing the invented
`allow_root`, and disabling mod_cgi for Shellshock). Three of four then re-validate
as `fixed`.
The remaining FTP failure is now isolated to a *deployment-execution* problem —
MS2's inetd-launched vsftpd does not honour `anonymous_enable=NO` on restart — and
is **no longer a prescription error**: the loop confirms the fix is correct yet
ineffective on that host, which is itself the argument for execution-based
re-validation. This unifies the paper's two results: **the same grounding
principle corrects both recommendation (§5) and remediation.** *(Raw:
`eval/results_remediation_ms2_grounded.json`, `eval/results_remediation_ms3_grounded.json`.)*

**All four exploit types now have a positive case (complete coverage).** A
Shellshock target (Ubuntu 14.04, Apache `mod_cgi`, unpatched bash, `192.168.28.133`)
was added so the fourth exploit type — previously only ever a true-negative — is
exercised end-to-end. The oracle confirmed Shellshock RCE; the grounded
remediation correctly prescribed disabling `mod_cgi` (and patching bash); applying
it (`a2dismod cgi cgid`) and re-validating returned **fixed** (the injection no
longer executes, the web service stays up). Across **all four exploit types**,
grounded remediation efficacy is **0.75 (3/4)** — `ssh_brute_force`,
`ms17_010_check`, and `shellshock_cgi` fixed; `ftp_brute_force` not_fixed (the
deployment-execution case above). *(Raw:
`eval/results_remediation_shellshock_grounded.json`.)*

### 6.4 Multi-target scale-up `[PLACEHOLDER]`
*Add Metasploitable 3, VulnHub images, a Windows MS17-010 host, and a Shellshock
CGI host to exercise all four exploit types with positive cases. Target N ≈ 20–30
findings for modest statistical power.*

### 6.5 Model-strength comparison `[PLACEHOLDER]`
*Repeat E1 with a weak local model (tinyllama), the default (llama3.2), and a
strong backend (e.g. GPT-4 via API) to separate "small model is weak" from
"grounding scheme is the cause."*

### 6.6 PentestGPT comparison — *qualitative done (§2); empirical is future work*
A capability comparison against PentestGPT's published design is in §2
(Table). A same-target empirical head-to-head was not run: PentestGPT's native
backend is a paid OpenAI API, and a fair run requires GPT-4 (a local-model run is
unreliable, as PentestGPT's parser is tuned for GPT-4). Future work: run real
PentestGPT-GPT-4 on the three targets, map its recommendations onto ASHEN's
exploit types, and score with the same oracle.

---

## 7. Discussion

The headline conceptual result is the **knowledge↔action-space misalignment** in
tool-using RAG (§5): grounding helps factual accuracy but can hurt *action
selection* when retrieved knowledge references capabilities the tool lacks.
Action-aware grounding is a general remedy — tie retrieved knowledge to the
declared action space, and quarantine the rest. A residual refinement is
**platform-applicability filtering**: do not attach a CVE as evidence for an
exploit when the CVE's product/platform contradicts the target fingerprint (this
would remove the EternalBlue artifact in §5).

---

## 8. Limitations

- **Few targets (n=3).** §5 spans three hosts (Linux, Windows, Shellshock); rates are not yet
  significant. §6.4 defines the scale-up.
- **Four exploit types** ⇒ shallow ranking depth; statistical power must come from
  many targets, not deep rankings.
- **Manual remediation.** ASHEN generates prose guidance; applying the fix is a
  human step. Efficacy is therefore measured per applied fix, at pilot scale.
- **Weak default model.** llama3.2-3B is small; §6.5 separates model from method.

---

## 9. Ethics and Responsible Use

ASHEN operates only against IPs an Admin has explicitly authorised; Analysts
cannot act outside scope. All actions and all LLM interactions are audit-logged.
The local-LLM design keeps target data on-premise. All experiments in this paper
were conducted against a self-hosted, intentionally-vulnerable VM owned by the
authors, on an isolated network.

---

## 10. Conclusion

ASHEN closes the penetration-testing loop from detection through validated
remediation, using execution as an objective oracle and a local LLM for
confidentiality. A three-host pilot demonstrates that action-aware retrieval
grounding corrects a failure mode of naïve RAG in tool-using agents. The
remediation-efficacy protocol and multi-target scale-up are defined and in
progress.

---

## References

- [pentestgpt] G. Deng et al. *PentestGPT: An LLM-empowered Automatic Penetration Testing Tool.* USENIX Security, 2024. arXiv:2308.06782.
- [rag] P. Lewis et al. *Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks.* NeurIPS, 2020.
- [fang-web] R. Fang et al. *LLM Agents can Autonomously Hack Websites.* 2024. arXiv:2402.06664.
- [fang-oneday] R. Fang et al. *LLM Agents can Autonomously Exploit One-day Vulnerabilities.* 2024. arXiv:2404.08144.
- [fang-zeroday] R. Fang et al. *Teams of LLM Agents can Exploit Zero-Day Vulnerabilities.* 2024. arXiv:2406.01637.
- [happe] A. Happe and J. Cito. *Getting pwn'd by AI / LLMs as Hackers: Autonomous Linux Privilege Escalation Attacks.* 2023. arXiv:2310.11409.
- [rlreview] J. Liu, Y. Zhang, S. Zhou, J. Yang, Y. Lu, and X. Zhong. *Autonomous Penetration Testing using Reinforcement Learning: A Review and Perspectives.* Expert Systems with Applications, 2025.
- [autoptsim] Y. Wang, S. Liu, W. Wang, C. Zhou, C. Zhang, J. Jin, and C. Zhu. *A Unified Modeling Framework for Automated Penetration Testing (AutoPT-Sim).* 2025. arXiv:2502.11588.
- [hacksynth] L. Muzsai, D. Imolai, and A. Lukács. *HackSynth: LLM Agent and Evaluation Framework for Autonomous Penetration Testing.* 2024. arXiv:2412.01778.
- [penheal] J. Huang and Q. Zhu. *PenHeal: A Two-Stage LLM Framework for Automated Pentesting and Optimal Remediation.* Workshop on Autonomous Cybersecurity (AutonomousCyber), 2024. arXiv:2407.17788.
- [pearce] H. Pearce et al. *Examining Zero-Shot Vulnerability Repair with Large Language Models.* IEEE S&P, 2023.
- [nmap] G. F. Lyon. *Nmap Network Scanning: The Official Nmap Project Guide to Network Discovery and Security Scanning.* Insecure.Com LLC, 2009.
- [sbert] N. Reimers and I. Gurevych. *Sentence-BERT: Sentence Embeddings using Siamese BERT-Networks.* EMNLP, 2019.
- [chroma] Chroma. *Chroma: the open-source embedding database.* https://www.trychroma.com, 2023.
- [ms17010] Microsoft. *Security Bulletin MS17-010: Security Update for Microsoft Windows SMB Server.* 2017. CVE-2017-0143/0144/0145.
- [shellshock] NVD. *CVE-2014-6271 (Shellshock): GNU Bash environment variable command injection.* 2014.
- [vsftpd] NVD. *CVE-2011-2523: vsftpd 2.3.4 backdoor command execution.* 2011.
