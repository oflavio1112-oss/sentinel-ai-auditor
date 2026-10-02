import { createServerFn } from "@tanstack/react-start";

export interface BriefPayload {
  title: string;
  riskScore: number;
  stats: {
    packages: number;
    findings: number;
    critical: number;
    high: number;
    medium: number;
    malware: number;
    secrets: number;
  };
  findings: {
    severity: string;
    kind: string;
    title: string;
    packageName?: string;
    osvId?: string;
    fixedVersion?: string;
  }[];
}

export const briefScan = createServerFn({ method: "POST" })
  .validator((input: BriefPayload) => input)
  .handler(async ({ data }) => {
    const apiKey = process.env.XAI_API_KEY;
    if (!apiKey) return { ok: false as const, error: "IA indisponível neste ambiente." };

    const top = data.findings.slice(0, 14);
    const prompt = `Você é um analista de AppSec. Escreva em português do Brasil, tom direto, sem emoji.
Resumo do scan "${data.title}": risco ${data.riskScore}/100, ${data.stats.packages} pacotes, ${data.stats.findings} achados (crítico ${data.stats.critical}, alto ${data.stats.high}, malware ${data.stats.malware}, segredos ${data.stats.secrets}).
Achados:
${top.map((f) => `- [${f.severity}/${f.kind}] ${f.title}${f.packageName ? ` (${f.packageName})` : ""}${f.osvId ? ` ${f.osvId}` : ""}${f.fixedVersion ? ` fix:${f.fixedVersion}` : ""}`).join("\n")}

Entregue:
1) veredito em 2 frases
2) 4 ações priorizadas
3) o que pode esperar (falsos positivos)`;

    const res = await fetch("https://api.x.ai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: "grok-4.5",
        max_tokens: 700,
        temperature: 0.2,
        messages: [{ role: "user", content: prompt }],
      }),
    });
    if (!res.ok) return { ok: false as const, error: `xAI ${res.status}` };
    const body = (await res.json()) as { choices?: { message?: { content?: string } }[] };
    const text = body.choices?.[0]?.message?.content?.trim() ?? "";
    if (!text) return { ok: false as const, error: "Resposta vazia da IA." };
    return { ok: true as const, text };
  });
