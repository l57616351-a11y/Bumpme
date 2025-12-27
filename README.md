import type { Express } from "express";
import { createServer, type Server } from "http";
import { dbStorage as storage } from "./dbStorage";
import {
  insertUserSchema,
  insertAppSchema,
  insertFileSchema,
  insertMessageSchema,
} from "@shared/schema";
import { createHash } from "crypto";
import { WebSocketServer, WebSocket } from "ws";
import OpenAI from "openai";
import fs from "fs";
import path from "path";

const openai = new OpenAI({
  apiKey: process.env.AI_INTEGRATIONS_OPENAI_API_KEY,
  baseURL: process.env.AI_INTEGRATIONS_OPENAI_BASE_URL,
});

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {
  // Authentication routes
  app.post("/api/signup", async (req, res) => {
    try {
      const result = insertUserSchema.safeParse(req.body);
      if (!result.success) {
        return res
          .status(400)
          .json({ error: "Invalid input", details: result.error.issues });
      }

      const existingUser = await storage.getUserByEmail(result.data.email);
      if (existingUser) {
        return res.status(409).json({ error: "User already exists" });
      }

      const user = await storage.createUser(result.data);
      await storage.logAudit("signup", user.id, { email: user.email });
      res.status(201).json({
        id: user.id,
        email: user.email,
        role: user.role,
        plan: user.plan,
      });
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.post("/api/login", async (req, res) => {
    try {
      const { email, password } = req.body;
      if (!email || !password) {
        return res
          .status(400)
          .json({ error: "Email and password are required" });
      }

      const user = await storage.getUserByEmail(email);
      if (!user) {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      const hashedPassword = createHash("sha256").update(password).digest("hex");
      if (user.password !== hashedPassword) {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      res.json({
        id: user.id,
        email: user.email,
        role: user.role,
        plan: user.plan,
      });
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // Apps routes
  app.get("/api/apps", async (req, res) => {
    try {
      const ownerId = req.query.ownerId as string | undefined;
      if (ownerId) {
        const apps = await storage.getAppsByOwner(ownerId);
        res.json(apps);
      } else {
        const apps = await storage.getApps();
        res.json(apps);
      }
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.get("/api/apps/published", async (req, res) => {
    try {
      const apps = await storage.getPublishedApps();
      res.json(apps);
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.get("/api/apps/:id", async (req, res) => {
    try {
      const appData = await storage.getAppById(req.params.id);
      if (!appData) {
        return res.status(404).json({ error: "App not found" });
      }
      res.json(appData);
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.post("/api/apps", async (req, res) => {
    try {
      const ownerId = (req.headers["x-user-id"] as string) || req.body.ownerId;
      const { ownerId: _omit, ...appData } = req.body;
      const result = insertAppSchema.safeParse(appData);
      if (!result.success) {
        return res
          .status(400)
          .json({ error: "Invalid input", details: result.error.issues });
      }

      if (!ownerId) {
        return res.status(400).json({ error: "Please log in to create an app" });
      }

      const created = await storage.createApp(result.data, ownerId);
      await storage.logAudit("app_created", ownerId, {
        appId: created.id,
        appName: created.name,
      });
      res.status(201).json(created);
    } catch (error) {
      console.error("Error creating app:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.patch("/api/apps/:id", async (req, res) => {
    try {
      const updated = await storage.updateApp(req.params.id, req.body);
      if (!updated) {
        return res.status(404).json({ error: "App not found" });
      }
      res.json(updated);
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.delete("/api/apps/:id", async (req, res) => {
    try {
      const deleted = await storage.deleteApp(req.params.id);
      if (!deleted) {
        return res.status(404).json({ error: "App not found" });
      }
      res.status(204).send();
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // Pricing routes
  app.get("/api/pricing", async (req, res) => {
    try {
      const pricing = await storage.getPricing();
      res.json(pricing);
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // Auth helper - extracts user from header
  const getAuthUser = async (req: any) => {
    const userId = req.headers["x-user-id"] as string;
    if (!userId) return null;
    return storage.getUser(userId);
  };

  // Middleware - requires authenticated user
  const requireAuth = async (req: any, res: any, next: any) => {
    const user = await getAuthUser(req);
    if (!user) {
      return res.status(401).json({ error: "Authentication required" });
    }
    req.authUser = user;
    next();
  };

  // Middleware - requires staff or higher role
  const requireStaff = async (req: any, res: any, next: any) => {
    const user = await getAuthUser(req);
    if (!user) {
      return res.status(401).json({ error: "Authentication required" });
    }
    if (!["staff", "admin", "owner"].includes(user.role)) {
      return res.status(403).json({ error: "Staff access required" });
    }
    req.authUser = user;
    next();
  };

  // Middleware - requires admin or owner role
  const requireAdmin = async (req: any, res: any, next: any) => {
    const user = await getAuthUser(req);
    if (!user) {
      return res.status(401).json({ error: "Authentication required" });
    }
    if (!["admin", "owner"].includes(user.role)) {
      return res.status(403).json({ error: "Admin access required" });
    }
    req.authUser = user;
    next();
  };

  // Middleware - requires owner role only
  const requireOwner = async (req: any, res: any, next: any) => {
    const user = await getAuthUser(req);
    if (!user) {
      return res.status(401).json({ error: "Authentication required" });
    }
    if (user.role !== "owner") {
      return res.status(403).json({ error: "Owner access required" });
    }
    req.authUser = user;
    next();
  };

  // AI Moderation route
  app.post("/api/ai/check", requireAuth, async (req, res) => {
    try {
      const { code } = req.body;
      if (!code) {
        return res.status(400).json({ error: "Code is required" });
      }

      const result = storage.moderateCode(code);
      if (result.status === "Blocked") {
        await storage.logAudit("ai_flag", (req as any).authUser?.id, {
          result: result.reason,
        });
      }
      res.json(result);
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // Staff route - publish apps
  app.post("/api/apps/publish/:id", requireStaff, async (req, res) => {
    try {
      const appData = await storage.getAppById(req.params.id);
      if (!appData) {
        return res.status(404).json({ error: "App not found" });
      }
      const updatedApp = await storage.updateApp(req.params.id, {
        published: true,
      });
      await storage.logAudit("app_published", (req as any).authUser?.id, {
        appId: appData.id,
        appName: appData.name,
      });
      res.json(updatedApp);
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // Owner routes - price management
  app.post("/api/owner/prices", requireOwner, async (req, res) => {
    try {
      const { prodigy, mastermind, team } = req.body;
      const pricing = await storage.updatePricing({ prodigy, mastermind, team });
      await storage.logAudit("prices_changed", (req as any).authUser?.id, {
        prodigy,
        mastermind,
        team,
      });
      res.json(pricing);
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // Upgrade plan route
  app.post("/api/upgrade", requireAuth, async (req, res) => {
    try {
      const { plan } = req.body;
      const allowedPlans = ["free", "prodigy", "mastermind", "team"];
      if (!plan || !allowedPlans.includes(plan)) {
        return res.status(400).json({ error: "Invalid plan" });
      }
      const user = await storage.updateUser((req as any).authUser.id, { plan });
      await storage.logAudit("upgrade", (req as any).authUser.id, { plan });
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      const { password, ...safeUser } = user;
      res.json(safeUser);
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // Admin routes
  app.get("/api/admin/stats", requireAdmin, async (req, res) => {
    try {
      const stats = await storage.getAdminStats();
      res.json(stats);
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.get("/api/admin/users", requireAdmin, async (req, res) => {
    try {
      const users = await storage.listAllUsers();
      const safeUsers = users.map(({ password, ...user }) => user);
      res.json(safeUsers);
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.patch("/api/admin/users/:id", requireAdmin, async (req, res) => {
    try {
      const { role, plan, status } = req.body;
      const allowedRoles = ["user", "staff", "admin", "owner"];
      const allowedPlans = ["free", "prodigy", "mastermind", "team"];
      const allowedStatuses = ["active", "suspended"];

      const updates: Record<string, string> = {};
      if (role && allowedRoles.includes(role)) updates.role = role;
      if (plan && allowedPlans.includes(plan)) updates.plan = plan;
      if (status && allowedStatuses.includes(status)) updates.status = status;

      if (Object.keys(updates).length === 0) {
        return res.status(400).json({ error: "No valid updates provided" });
      }

      const user = await storage.updateUser(req.params.id, updates);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      const { password, ...safeUser } = user;
      res.json(safeUser);
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.get("/api/admin/apps", requireAdmin, async (req, res) => {
    try {
      const apps = await storage.getApps();
      res.json(apps);
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.patch("/api/admin/apps/:id", requireAdmin, async (req, res) => {
    try {
      const { published, featured } = req.body;
      const updates: Record<string, boolean> = {};
      if (typeof published === "boolean") updates.published = published;
      if (typeof featured === "boolean") updates.featured = featured;

      if (Object.keys(updates).length === 0) {
        return res.status(400).json({ error: "No valid updates provided" });
      }

      const updatedApp = await storage.updateApp(req.params.id, updates);
      if (!updatedApp) {
        return res.status(404).json({ error: "App not found" });
      }
      res.json(updatedApp);
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.delete("/api/admin/apps/:id", requireAdmin, async (req, res) => {
    try {
      const deleted = await storage.deleteApp(req.params.id);
      if (!deleted) {
        return res.status(404).json({ error: "App not found" });
      }
      await storage.logAudit("app_deleted", (req as any).authUser?.id, {
        appId: req.params.id,
      });
      res.status(204).send();
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.get("/api/admin/audit", requireAdmin, async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string) || 50;
      const logs = await storage.getAuditLogs(limit);
      res.json(logs);
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // File management routes
  app.get("/api/apps/:appId/files", async (req, res) => {
    try {
      const files = await storage.getFilesByApp(req.params.appId);
      res.json(files);
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.get("/api/files/:id", async (req, res) => {
    try {
      const file = await storage.getFileById(req.params.id);
      if (!file) {
        return res.status(404).json({ error: "File not found" });
      }
      res.json(file);
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.post("/api/apps/:appId/files", requireAuth, async (req, res) => {
    try {
      const result = insertFileSchema.safeParse(req.body);
      if (!result.success) {
        return res
          .status(400)
          .json({ error: "Invalid input", details: result.error.issues });
      }
      const file = await storage.createFile(result.data, req.params.appId);
      res.status(201).json(file);
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.patch("/api/files/:id", requireAuth, async (req, res) => {
    try {
      const file = await storage.updateFile(req.params.id, req.body);
      if (!file) {
        return res.status(404).json({ error: "File not found" });
      }
      res.json(file);
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.delete("/api/files/:id", requireAuth, async (req, res) => {
    try {
      const deleted = await storage.deleteFile(req.params.id);
      if (!deleted) {
        return res.status(404).json({ error: "File not found" });
      }
      res.status(204).send();
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // Message/Chat routes
  app.get("/api/apps/:appId/messages", async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string) || 50;
      const msgs = await storage.getMessages(req.params.appId, limit);
      res.json(msgs);
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.post("/api/apps/:appId/messages", requireAuth, async (req, res) => {
    try {
      const result = insertMessageSchema.safeParse(req.body);
      if (!result.success) {
        return res
          .status(400)
          .json({ error: "Invalid input", details: result.error.issues });
      }
      const message = await storage.createMessage(
        result.data,
        (req as any).authUser.id,
        req.params.appId
      );
      wss.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
          client.send(JSON.stringify({ type: "message", data: message }));
        }
      });
      res.status(201).json(message);
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // App run routes
  app.post("/api/apps/:appId/run", requireAuth, async (req, res) => {
    try {
      const appData = await storage.getAppById(req.params.appId);
      if (!appData) {
        return res.status(404).json({ error: "App not found" });
      }

      const modResult = storage.moderateCode(appData.code || "");
      if (modResult.status === "Blocked") {
        return res.status(400).json({ error: modResult.reason });
      }

      const run = await storage.createAppRun(
        req.params.appId,
        (req as any).authUser?.id
      );

      let output = "";
      let error: any = null;
      const startTime = Date.now();

      try {
        const safeCode = `
          const console = {
            log: (...args) => { output += args.join(' ') + '\\n'; },
            error: (...args) => { output += 'ERROR: ' + args.join(' ') + '\\n'; },
            warn: (...args) => { output += 'WARN: ' + args.join(' ') + '\\n'; },
          };
          let output = '';
          ${appData.code || ""}
          output;
        `;
        const fn = new Function(safeCode);
        output = fn() || "Code executed successfully";
      } catch (e: any) {
        error = e.message;
        output = `Error: ${e.message}`;
      }

      const duration = Date.now() - startTime;
      const updatedRun = await storage.updateAppRun(run.id, {
        status: error ? "error" : "completed",
        output,
        error,
        duration,
      });

      res.json(updatedRun);
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.get("/api/apps/:appId/runs", async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string) || 20;
      const runs = await storage.getAppRuns(req.params.appId, limit);
      res.json(runs);
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // AI Credits routes
  app.get("/api/users/:userId/ai-credits", requireAuth, async (req, res) => {
    try {
      const requestingUserId = req.headers["x-user-id"] as string;
      if (requestingUserId !== req.params.userId) {
        const requestingUser = await storage.getUser(requestingUserId);
        if (
          !requestingUser ||
          (requestingUser.role !== "admin" && requestingUser.role !== "owner")
        ) {
          return res.status(403).json({ error: "Access denied" });
        }
      }
      const credits = await storage.checkAICredits(req.params.userId);
      res.json(credits);
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.post(
    "/api/users/:userId/ai-credits/use",
    requireAuth,
    async (req, res) => {
      try {
        const success = await storage.useAICredit(req.params.userId);
        if (!success) {
          return res.status(429).json({
            error: "AI credit limit reached",
            message: "Upgrade your plan for more AI credits",
          });
        }
        const credits = await storage.checkAICredits(req.params.userId);
        res.json(credits);
      } catch (error) {
        res.status(500).json({ error: "Internal server error" });
      }
    }
  );

  // =========================
  // AI SAFETY + PLANNING + REPORTING
  // =========================
  const TOS_NOTICE =
    "This notice is to inform you that your account has been placed under temporary restriction due to a suspected breach of the Terms of Service or the identification of anomalous activity. Our staff is currently reviewing the matter.";

  // Fast server-side abuse heuristic (in addition to model refusal)
  const looksLikeAbuse = (text: string): boolean => {
    const t = (text || "").toLowerCase();
    const patterns: RegExp[] = [
      /\b(hack|hacking|exploit|exploitation|0day|zero[-\s]?day|rce|xss|sqli|sql injection|csrf|ssrf)\b/i,
      /\b(keylogger|stealer|credential|password dump|token dump|session hijack)\b/i,
      /\b(phishing|social engineering|bypass|bypass auth|crack|破解|ddos|botnet)\b/i,
      /\b(malware|ransomware|trojan|worm|backdoor|rootkit)\b/i,
      /\b(bruteforce|brute force|credential stuffing)\b/i,
      /\b(stalk|dox|doxx|swat|swatting)\b/i,
    ];
    return patterns.some((p) => p.test(t));
  };

  const restrictAndReport = async (params: {
    userId: string;
    appId?: string;
    reason: string;
    lastUserMessage: string;
  }) => {
    const { userId, appId, reason, lastUserMessage } = params;

    // 1) Restrict account
    try {
      await storage.updateUser(userId, { status: "suspended" } as any);
    } catch (e) {
      // continue regardless
    }

    // 2) Audit log (owner can view in admin audit screen)
    try {
      await storage.logAudit("tos_restriction", userId, {
        reason,
        appId: appId ?? null,
        lastUserMessage,
      });
    } catch (e) {}

    // 3) In-app system report (visible anywhere the app chat is visible)
    if (appId) {
      try {
        await storage.createMessage(
          {
            content:
              `🚨 SECURITY REPORT (Auto)\n` +
              `User: ${userId}\n` +
              `Reason: ${reason}\n\n` +
              `Last message:\n${lastUserMessage}`,
            channelType: "system",
          },
          "ai-guard",
          appId
        );
      } catch (e) {}
    }
  };

  // Universal coding assistant prompt with multi-step planning + self-testing
  const UNIVERSAL_AI_SYSTEM_PROMPT = {
    role: "system" as const,
    content: `
You are an elite principal software engineer with universal language expertise.

You support ALL programming languages and paradigms, including:
Java, JavaScript, TypeScript, Python, C/C++, C#, Go, Rust, Kotlin, Swift, PHP, Ruby, Bash, SQL, and more.

SAFETY & TOS COMPLIANCE (ABSOLUTE):
- You must refuse requests involving hacking, exploits, malware, credential theft, privacy invasion, or ToS evasion.
- If the user appears to be attempting any of the above, output EXACTLY this token and nothing else:
__TOS_VIOLATION__

MULTI-STEP PLANNING (MANDATORY, INTERNAL):
1) Understand the request + constraints
2) Ask ONE clarifying question only if required
3) Propose a plan
4) Validate the plan
5) Write code
6) Self-test mentally: syntax, runtime, edge cases, error paths
7) Fix issues
8) Only then respond

OUTPUT REQUIREMENTS:
- If you output code, also include tests and a short CI-style "Test Report" (cases + expected results).
- Code must be complete & runnable; no placeholders or pseudo-code.
- Never hallucinate libraries, file paths, or APIs.
`,
  };

  // Owner AI: multi-step planning first, then change-set JSON
  const OWNER_AI_PLAN_PROMPT = (allFiles: string[]) => ({
    role: "system" as const,
    content: `
You are the OWNER AI for Ginger AI Builder. You have full authority to change the project.

You must do MULTI-STEP PLANNING before proposing any code changes.

AVAILABLE FILES:
${allFiles.join("\n")}

Return JSON ONLY in this format:
{
  "summary": "what the user wants",
  "plan": ["step 1", "step 2", "..."],
  "filesLikelyTouched": ["path1", "path2"],
  "testsToRun": ["test 1", "test 2"],
  "risks": ["risk 1", "risk 2"]
}

Rules:
- Minimal blast radius unless user explicitly requests a refactor.
- Do not propose unsafe/ToS-violating changes.
`,
  });

  const OWNER_AI_EXEC_PROMPT = (allFiles: string[], planJson: string) => ({
    role: "system" as const,
    content: `
You are the OWNER AI for Ginger AI Builder. You have full authority to edit the codebase.

AVAILABLE FILES:
${allFiles.join("\n")}

You MUST follow this plan:
${planJson}

Before returning changes (internal):
- Validate imports/references
- Ensure changes are consistent
- Provide tests and a "Test Report" inside the explanation (not as separate files unless needed)

When the user asks you to make changes, return JSON ONLY in this exact structure:
{
  "explanation": "What you're going to do, why, and CI-style Test Report (cases + expected results)",
  "changes": [
    { "file": "path/to/file", "action": "edit" | "create" | "delete", "content": "FULL new content" }
  ]
}

If the user just asks a question, respond normally without the JSON structure.
Never output unsafe/ToS-violating content.
`,
  });

  // AI Chat routes
  app.post("/api/ai/chat", requireAuth, async (req, res) => {
    try {
      const userId = req.headers["x-user-id"] as string;
      const { messages, appId } = req.body;

      if (!messages || !Array.isArray(messages)) {
        return res.status(400).json({ error: "Messages array is required" });
      }

      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(401).json({ error: "User not found" });
      }

      const lastUserMessage = String(messages[messages.length - 1]?.content || "");

      // Server-side safety gate (fast)
      if (looksLikeAbuse(lastUserMessage)) {
        await restrictAndReport({
          userId,
          appId,
          reason: "Abuse heuristic triggered (suspected hacking/ToS evasion).",
          lastUserMessage,
        });
        return res.json({ message: TOS_NOTICE });
      }

      // Credits enforcement (owners exempt)
      if (user.role !== "owner") {
        const creditCheck = await storage.checkAICredits(userId);
        if (!creditCheck.canUse) {
          return res.status(429).json({
            error: "AI credit limit reached",
            message: "Upgrade your plan for more AI credits",
          });
        }
        await storage.useAICredit(userId);
      }

      // Persistent memory: include recent app messages (if appId provided)
      let memoryContext: { role: "user" | "assistant"; content: string }[] = [];
      if (appId) {
        try {
          const recent = await storage.getMessages(appId, 30);
          memoryContext = recent
            .slice()
            .reverse()
            .map((m: any) => {
              const isAssistant = m.senderId === "ai-assistant" || m.isAI === true;
              return {
                role: isAssistant ? "assistant" : "user",
                content: String(m.content || "").slice(0, 4000),
              };
            });
        } catch (e) {
          memoryContext = [];
        }
      }

      const response = await openai.chat.completions.create({
        model: "gpt-4o-mini",
        messages: [
          UNIVERSAL_AI_SYSTEM_PROMPT,
          ...memoryContext,
          ...messages.map((m: { role: string; content: string }) => ({
            role: m.role as "user" | "assistant",
            content: m.content,
          })),
        ],
        max_tokens: 2048,
      });

      const aiMessage = (response.choices[0]?.message?.content || "").trim();

      // AI-side TOS signal (fallback)
      if (aiMessage === "__TOS_VIOLATION__") {
        await restrictAndReport({
          userId,
          appId,
          reason: "AI flagged the request as a ToS violation.",
          lastUserMessage,
        });
        return res.json({ message: TOS_NOTICE });
      }

      if (appId) {
        await storage.createMessage(
          {
            content: lastUserMessage,
            channelType: "ai",
          },
          userId,
          appId
        );
        await storage.createMessage(
          {
            content: aiMessage,
            channelType: "ai",
          },
          "ai-assistant",
          appId
        );
      }

      res.json({ message: aiMessage });
    } catch (error) {
      console.error("AI chat error:", error);
      res.status(500).json({ error: "Failed to process AI request" });
    }
  });

  // Owner AI endpoint - has full file system access
  app.post("/api/owner/ai", requireAuth, async (req, res) => {
    try {
      const userId = req.headers["x-user-id"] as string;
      const user = await storage.getUser(userId);

      if (!user || user.role !== "owner") {
        return res.status(403).json({ error: "Only owner can use this AI" });
      }

      const { messages } = req.body;

      if (!messages || !Array.isArray(messages)) {
        return res.status(400).json({ error: "Messages array is required" });
      }

      const projectRoot = process.cwd();
      const clientDir = path.join(projectRoot, "client", "src");
      const serverDir = path.join(projectRoot, "server");
      const sharedDir = path.join(projectRoot, "shared");

      const getAllFiles = (dir: string, prefix = ""): string[] => {
        const files: string[] = [];
        try {
          const items = fs.readdirSync(dir);
          for (const item of items) {
            const fullPath = path.join(dir, item);
            const relativePath = prefix ? `${prefix}/${item}` : item;
            const stat = fs.statSync(fullPath);
            if (stat.isDirectory() && !item.startsWith(".") && item !== "node_modules") {
              files.push(...getAllFiles(fullPath, relativePath));
            } else if (stat.isFile() && (item.endsWith(".ts") || item.endsWith(".tsx") || item.endsWith(".css"))) {
              files.push(relativePath);
            }
          }
        } catch (e) {}
        return files;
      };

      const clientFiles = getAllFiles(clientDir, "client/src");
      const serverFiles = getAllFiles(serverDir, "server");
      const sharedFiles = getAllFiles(sharedDir, "shared");
      const allFiles = [...clientFiles, ...serverFiles, ...sharedFiles];

      const lastUserMessage = String(messages[messages.length - 1]?.content || "");
      if (looksLikeAbuse(lastUserMessage)) {
        await restrictAndReport({
          userId,
          appId: undefined,
          reason: "Abuse heuristic triggered in owner endpoint (suspected hacking/ToS evasion).",
          lastUserMessage,
        });
        return res.json({ message: TOS_NOTICE, files: allFiles });
      }

      // Step 1: Planning
      const planResponse = await openai.chat.completions.create({
        model: "gpt-4o",
        messages: [
          OWNER_AI_PLAN_PROMPT(allFiles),
          ...messages.map((m: { role: string; content: string }) => ({
            role: m.role as "user" | "assistant",
            content: m.content,
          })),
        ],
        max_tokens: 1200,
      });

      const planText = (planResponse.choices[0]?.message?.content || "").trim();

      // Step 2: Execute using the plan
      const execResponse = await openai.chat.completions.create({
        model: "gpt-4o",
        messages: [
          OWNER_AI_EXEC_PROMPT(allFiles, planText),
          ...messages.map((m: { role: string; content: string }) => ({
            role: m.role as "user" | "assistant",
            content: m.content,
          })),
        ],
        max_tokens: 4096,
      });

      const aiMessage = (execResponse.choices[0]?.message?.content || "").trim();

      // If AI flags ToS (fallback)
      if (aiMessage === "__TOS_VIOLATION__") {
        await restrictAndReport({
          userId,
          appId: undefined,
          reason: "Owner AI flagged the request as a ToS violation.",
          lastUserMessage,
        });
        return res.json({ message: TOS_NOTICE, files: allFiles });
      }

      // Safety check: if AI returns a change-set JSON, run basic moderation on file contents
      try {
        const parsed = JSON.parse(aiMessage);
        if (parsed?.changes && Array.isArray(parsed.changes)) {
          for (const ch of parsed.changes) {
            if (ch?.action === "edit" || ch?.action === "create") {
              const content = String(ch.content || "");
              const mod = storage.moderateCode(content);
              if (mod.status === "Blocked") {
                await storage.logAudit("owner_ai_change_blocked", userId, {
                  reason: mod.reason,
                  file: ch.file,
                });
                return res.status(400).json({
                  error: "Owner AI output contained blocked content",
                  reason: mod.reason,
                });
              }
            }
          }
        }
      } catch (e) {
        // Non-JSON responses are allowed for Q&A mode
      }

      res.json({ message: aiMessage, files: allFiles, plan: planText });
    } catch (error) {
      console.error("Owner AI error:", error);
      res.status(500).json({ error: "Failed to process Owner AI request" });
    }
  });

  // Templates routes
  app.get("/api/templates", async (_req, res) => {
    const templates = [
      {
        id: "hello-world",
        name: "Hello World",
        description: "Basic starter template",
        category: "getting-started",
      },
      {
        id: "todo",
        name: "Todo App",
        description: "Simple task manager",
        category: "productivity",
      },
      {
        id: "counter",
        name: "Counter App",
        description: "Counter example",
        category: "getting-started",
      },
      {
        id: "data-viz",
        name: "Data Visualization",
        description: "Chart template",
        category: "analytics",
      },
    ];
    res.json(templates);
  });

  const templatesData = [
    {
      id: "hello-world",
      name: "Hello World",
      description: "Basic starter template",
      language: "javascript",
      files: [
        {
          name: "index.js",
          path: "/index.js",
          content:
            'console.log("Hello World!");\nconsole.log("Welcome to Ginger AI Builder");',
          language: "javascript",
        },
      ],
    },
    {
      id: "todo",
      name: "Todo App",
      description: "Simple task manager",
      language: "javascript",
      files: [
        {
          name: "todo.js",
          path: "/todo.js",
          content:
            'let todos = ["Learn JavaScript", "Build an app", "Deploy it"];\nfunction addTodo(todo) { todos.push(todo); }\nfunction listTodos() { console.log("Todos:"); todos.forEach((t, i) => console.log(`${i+1}. ${t}`)); }\nlistTodos();',
          language: "javascript",
        },
      ],
    },
    {
      id: "counter",
      name: "Counter App",
      description: "Counter example",
      language: "javascript",
      files: [
        {
          name: "counter.js",
          path: "/counter.js",
          content:
            'let score = 0;\nfunction update() { score++; console.log("Score:", score); }\nfor(let i = 0; i < 5; i++) update();',
          language: "javascript",
        },
      ],
    },
    {
      id: "data-viz",
      name: "Data Visualization",
      description: "Chart template",
      language: "javascript",
      files: [
        {
          name: "chart.js",
          path: "/chart.js",
          content:
            'const data = [{label: "A", value: 10}, {label: "B", value: 20}];\ndata.forEach(d => console.log(`${d.label}: ${"=".repeat(d.value)}`));',
          language: "javascript",
        },
      ],
    },
  ];

  app.post("/api/apps/from-template", requireAuth, async (req, res) => {
    try {
      const userId = req.headers["x-user-id"] as string;
      const { templateId, name } = req.body;

      const template = templatesData.find((t) => t.id === templateId);

      if (!template) {
        return res.status(404).json({
          error: "Template not found",
          available: templatesData.map((t) => t.id),
        });
      }

      const created = await storage.createApp(
        {
          name: name || template.name,
          description: template.description,
        },
        userId
      );

      for (const file of template.files) {
        await storage.createFile(
          {
            name: file.name,
            path: file.path,
            content: file.content,
            language: file.language,
            isFolder: false,
          },
          created.id
        );
      }

      res.json(created);
    } catch (error) {
      console.error("Error creating app from template:", error);
      res.status(500).json({ error: "Failed to create app from template" });
    }
  });

  // WebSocket setup for real-time chat
  const wss = new WebSocketServer({ server: httpServer, path: "/ws" });

  wss.on("connection", (ws) => {
    ws.on("message", async (data) => {
      try {
        const msg = JSON.parse(data.toString());
        if (msg.type === "ping") {
          ws.send(JSON.stringify({ type: "pong" }));
        }
      } catch (e) {
        console.error("WebSocket message error:", e);
      }
    });
  });

  return httpServer;
}
