export type AIProviderName = "groq" | "gemini";

export type ProviderAttempt<T> = {
  provider: AIProviderName;
  run: () => Promise<T>;
};

export function isFallbackEligible(error: unknown): boolean {
  if (typeof error !== "object" || error === null) {
    return false;
  }

  const details = error as {
    status?: unknown;
    statusCode?: unknown;
    code?: unknown;
    message?: unknown;
  };

  const status = Number(details.status ?? details.statusCode);

  // Rate limits and server errors may be recoverable.
  if (status === 429 || status >= 500) {
    return true;
  }

  // Don't hide invalid keys, invalid requests or other client errors.
  if (status >= 400 && status < 500) {
    return false;
  }

  const message = [
    details.code,
    details.message,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

    return /rate.?limit|quota|resource_exhausted|overloaded|timeout|timed out|econnreset|etimedout|econnrefused|fetch failed|network error|service unavailable|json_validate_failed|failed to generate json|max completion tokens reached/.test(
        message
    );
}

export async function runWithFallback<T>(
  attempts: ProviderAttempt<T>[],
  onFailure?: (
    provider: AIProviderName,
    error: unknown
  ) => void
): Promise<{
  provider: AIProviderName;
  fallbackUsed: boolean;
  result: T;
}> {
  if (attempts.length === 0) {
    throw new Error("No AI providers are configured.");
  }

  for (let index = 0; index < attempts.length; index++) {
    const attempt = attempts[index];

    try {
      const result = await attempt.run();

      return {
        provider: attempt.provider,
        fallbackUsed: index > 0,
        result,
      };
    } catch (error) {
      onFailure?.(attempt.provider, error);

      const hasAnotherProvider = index < attempts.length - 1;

      if (!hasAnotherProvider || !isFallbackEligible(error)) {
        throw error;
      }
    }
  }

  throw new Error("All configured AI providers failed.");
}