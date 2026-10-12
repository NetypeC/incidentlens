import { describe, expect, it, vi } from "vitest";
import { runWithFallback } from "./provider-fallback";

describe("AI provider fallback", () => {
  it("uses Gemini when Groq fails", async () => {
    const onFailure = vi.fn();

    const result = await runWithFallback(
      [
        {
          provider: "groq" as const,
          run: async () => {
            throw new Error("Simulated quota exhaustion");
          },
        },
        {
          provider: "gemini" as const,
          run: async () => ({
            summary: "Fallback analysis succeeded",
          }),
        },
      ],
      onFailure
    );

    expect(result.provider).toBe("gemini");
    expect(result.fallbackUsed).toBe(true);
    expect(result.result.summary).toBe(
      "Fallback analysis succeeded"
    );
    expect(onFailure).toHaveBeenCalledOnce();
  });

  it("does not call Gemini when Groq succeeds", async () => {
    const geminiRun = vi.fn(async () => "Gemini result");

    const result = await runWithFallback([
      {
        provider: "groq" as const,
        run: async () => "Groq result",
      },
      {
        provider: "gemini" as const,
        run: geminiRun,
      },
    ]);

    expect(result.provider).toBe("groq");
    expect(result.fallbackUsed).toBe(false);
    expect(result.result).toBe("Groq result");
    expect(geminiRun).not.toHaveBeenCalled();
  });

  it("reports failure when both providers fail", async () => {
    const groqRun = vi.fn(async () => {
        throw Object.assign(
        new Error("Groq unavailable"),
        { status: 503 }
        );
    });

    const geminiRun = vi.fn(async () => {
        throw Object.assign(
        new Error("Gemini unavailable"),
        { status: 503 }
        );
    });

    await expect(
        runWithFallback([
        {
            provider: "groq",
            run: groqRun,
        },
        {
            provider: "gemini",
            run: geminiRun,
        },
        ])
    ).rejects.toThrow("Gemini unavailable");

    expect(groqRun).toHaveBeenCalledOnce();
    expect(geminiRun).toHaveBeenCalledOnce();
    });
});