import { create } from "zustand";
import { persist } from "zustand/middleware";

export type EmailCategory =
  | "work"
  | "recruiter"
  | "newsletter"
  | "personal"
  | "finance"
  | "academic"
  | "promotional"
  | "spam";

export type UrgencyLevel = "critical" | "high" | "medium" | "low";
export type ToneType = "professional" | "friendly" | "urgent" | "aggressive" | "neutral" | "suspicious";

export type EmailAnalysis = {
  category: EmailCategory;
  urgency: UrgencyLevel;
  tone: ToneType;
  summary: string;
  deadlines: string[];
  actionItems: string[];
  isPhishing: boolean;
  phishingReason?: string;
  importanceScore: number; // 1-10
  draftReply?: string;
  analyzedAt: string;
};

export type EmailThread = {
  id: string;
  from: string;
  fromEmail: string;
  subject: string;
  preview: string;
  body: string;
  receivedAt: string;
  isRead: boolean;
  isStarred: boolean;
  analysis?: EmailAnalysis;
  // Agent workflow fields
  agentProcessed?: boolean;
  autoReplied?: boolean;
  autoReplySentText?: string;
  needsApproval?: boolean;
  approvedAndSent?: boolean;
};

type EmailStore = {
  emails: EmailThread[];
  geminiApiKey?: string;
  openaiApiKey?: string;
  agentEnabled: boolean;
  toggleAgent: () => void;
  markAgentProcessed: (id: string, patches: Partial<EmailThread>) => void;
  approveDraft: (id: string) => void;
  dismissDraft: (id: string) => void;
  addEmail: (email: Omit<EmailThread, "id">) => EmailThread;
  updateAnalysis: (id: string, analysis: EmailAnalysis) => void;
  setDraftReply: (id: string, text: string) => void;
  toggleRead: (id: string) => void;
  toggleStar: (id: string) => void;
  deleteEmail: (id: string) => void;
  setGeminiApiKey: (key: string) => void;
  setOpenaiApiKey: (key: string) => void;
};

const DEMO_EMAILS: EmailThread[] = [
  {
    id: "email-1",
    from: "Dr. Sarah Chen",
    fromEmail: "s.chen@university.edu",
    subject: "Final Project Submission — Deadline Extended to Friday",
    preview: "Good news! After reviewing the class progress, I've decided to extend the deadline for your final AI project...",
    body: `Hi everyone,

Good news! After reviewing the class progress and considering the complexity of the transformer architecture assignment, I've decided to extend the final project submission deadline.

New deadline: This Friday, May 30th at 11:59 PM

Requirements reminder:
- Full implementation of the attention mechanism
- Comparative analysis with at least 3 baseline models
- 10-page report in NeurIPS format
- Code submitted via GitHub with a README

Please make sure your code runs end-to-end before submission. I'll be holding extra office hours on Thursday from 2-5 PM.

Best,
Dr. Chen`,
    receivedAt: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
    isRead: false,
    isStarred: true,
  },
  {
    id: "email-2",
    from: "Alex Rivera",
    fromEmail: "alex.rivera@techstartup.io",
    subject: "Exciting Senior ML Engineer Opportunity — $180K + Equity",
    preview: "Hi! I came across your profile on LinkedIn and think you'd be a great fit for our Series B AI startup...",
    body: `Hi,

I came across your profile on LinkedIn and I'm genuinely impressed by your background in machine learning and distributed systems.

We're a Series B AI startup (just raised $40M) building the next generation of LLM infrastructure. We're looking for a Senior ML Engineer to join our founding team.

What we offer:
- $160K-$180K base salary
- 0.5-1.5% equity
- Full remote flexibility
- $5K learning stipend
- Top-tier health benefits

The role involves: model fine-tuning, inference optimization, and working directly with our CTO.

Would you be open to a 20-minute intro call this week? I have slots available Thursday and Friday afternoon.

Best,
Alex Rivera
Technical Recruiter | TechStartup.io`,
    receivedAt: new Date(Date.now() - 5 * 60 * 60 * 1000).toISOString(),
    isRead: false,
    isStarred: false,
  },
  {
    id: "email-3",
    from: "Bank of America",
    fromEmail: "noreply@b0famerica-secure.net",
    subject: "URGENT: Your account has been suspended — Verify NOW",
    preview: "Your Bank of America account has been temporarily suspended due to suspicious activity. Click here immediately...",
    body: `Dear Valued Customer,

Your Bank of America account has been temporarily suspended due to suspicious activity detected on your account.

To restore access, you must verify your identity IMMEDIATELY by clicking the link below:

>> VERIFY MY ACCOUNT NOW <<

http://boa-secure-verify.malicious-domain.xyz/login

If you do not verify within 24 hours, your account will be permanently closed and funds may be seized.

Bank of America Security Team`,
    receivedAt: new Date(Date.now() - 8 * 60 * 60 * 1000).toISOString(),
    isRead: false,
    isStarred: false,
  },
  {
    id: "email-4",
    from: "Marcus Thompson",
    fromEmail: "m.thompson@company.com",
    subject: "Q2 Sprint Review — Action Items for You",
    preview: "Hey, great standup today! Just wanted to follow up on the action items from our Q2 sprint review...",
    body: `Hey,

Great standup today! Just wanted to follow up on the action items from our Q2 sprint review:

Your action items:
1. Refactor the data pipeline by June 3rd
2. Write unit tests for the new recommendation engine
3. Schedule a technical review with the platform team before EOW
4. Update the architecture diagram in Confluence

The client demo is scheduled for June 10th so we need everything polished by June 8th at the latest.

Let me know if you have any blockers — happy to help.

Cheers,
Marcus`,
    receivedAt: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000).toISOString(),
    isRead: true,
    isStarred: false,
  },
  {
    id: "email-5",
    from: "The Batch — DeepLearning.AI",
    fromEmail: "batch@deeplearning.ai",
    subject: "The Batch: GPT-5 Released, Gemini Ultra 2 Benchmarks, and more",
    preview: "This week in AI: OpenAI drops GPT-5 with unprecedented reasoning capabilities, Google's Gemini Ultra 2...",
    body: `THE BATCH
Weekly AI News from DeepLearning.AI

This week's highlights:

🔥 GPT-5 Released
OpenAI announced GPT-5, boasting a 40% improvement on MMLU and near-human performance on the bar exam. Early access is now available for Plus subscribers.

📊 Gemini Ultra 2 Benchmarks
Google released benchmark results for Gemini Ultra 2, showing strong performance on multimodal reasoning tasks.

🤖 Mistral 8x22B Open-Sourced
Mistral AI released their largest open-source model, rivaling GPT-4 on many benchmarks.

📚 Paper of the Week
"Constitutional AI at Scale" — A new approach to aligning large language models using self-critique.

Stay curious,
The DeepLearning.AI Team`,
    receivedAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
    isRead: true,
    isStarred: false,
  },
  {
    id: "email-6",
    from: "Jordan Lee",
    fromEmail: "jordan@friend.com",
    subject: "Weekend plans? 🎉",
    preview: "Hey! Are you free this weekend? A few of us are planning a hike on Saturday and dinner after...",
    body: `Hey!

Are you free this weekend? A few of us are planning a hike on Saturday morning (starts around 9 AM at Muir Woods) and then dinner at that new Italian place downtown.

Let me know if you're in! We can carpool if needed.

Also — did you finish that project you were stressing about last week? Hope it went well 🤞

Talk soon,
Jordan`,
    receivedAt: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString(),
    isRead: true,
    isStarred: false,
  },
];

export const useEmailStore = create<EmailStore>()(
  persist(
    (set) => ({
      emails: DEMO_EMAILS,

      geminiApiKey: undefined,
      openaiApiKey: undefined,
      agentEnabled: false,

      toggleAgent: () => set((state) => ({ agentEnabled: !state.agentEnabled })),
      
      markAgentProcessed: (id, patches) => set((state) => ({
        emails: state.emails.map((e) => e.id === id ? { ...e, ...patches, agentProcessed: true } : e)
      })),

      approveDraft: (id) => set((state) => ({
        emails: state.emails.map((e) => e.id === id ? {
          ...e,
          needsApproval: false,
          approvedAndSent: true,
          isRead: true,
          autoReplySentText: e.analysis?.draftReply || "Approved response sent.",
        } : e)
      })),

      dismissDraft: (id) => set((state) => ({
        emails: state.emails.map((e) => e.id === id ? {
          ...e,
          needsApproval: false,
        } : e)
      })),

      addEmail: (data) => {
        const email: EmailThread = { ...data, id: crypto.randomUUID() };
        set((state) => ({ emails: [email, ...state.emails] }));
        return email;
      },

      updateAnalysis: (id, analysis) =>
        set((state) => ({
          emails: state.emails.map((e) => (e.id === id ? { ...e, analysis, isRead: true } : e)),
        })),

      setDraftReply: (id, text) =>
        set((state) => ({
          emails: state.emails.map((e) =>
            e.id === id
              ? {
                  ...e,
                  analysis: e.analysis
                    ? { ...e.analysis, draftReply: text }
                    : undefined,
                }
              : e
          ),
        })),

      toggleRead: (id) =>
        set((state) => ({
          emails: state.emails.map((e) => (e.id === id ? { ...e, isRead: !e.isRead } : e)),
        })),

      toggleStar: (id) =>
        set((state) => ({
          emails: state.emails.map((e) => (e.id === id ? { ...e, isStarred: !e.isStarred } : e)),
        })),

      deleteEmail: (id) =>
        set((state) => ({ emails: state.emails.filter((e) => e.id !== id) })),

      setGeminiApiKey: (key) => set({ geminiApiKey: key || undefined }),
      setOpenaiApiKey: (key) => set({ openaiApiKey: key || undefined }),
    }),
    { name: "jerry-email-store" }
  )
);
