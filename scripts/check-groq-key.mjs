const apiKey = process.env.GROQ_API_KEY?.trim();
const model =
  process.env.GROQ_MODEL || "openai/gpt-oss-20b";

if (!apiKey) {
  console.log("GROQ_API_KEY is missing.");
  process.exit(1);
}

try {
  const response = await fetch(
    "https://api.groq.com/openai/v1/models",
    {
      headers: {
        Authorization: `Bearer ${apiKey}`,
      },
      signal: AbortSignal.timeout(15000),
    }
  );

  console.log("HTTP status:", response.status);

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));

    console.log(
      "Groq error:",
      error.error?.message || "Request rejected"
    );

    process.exit(1);
  }

  const result = await response.json();
  const available = result.data?.some(
    (item) => item.id === model
  );

  console.log("API key accepted: Yes");
  console.log("Configured model:", model);
  console.log("Model available:", Boolean(available));
} catch (error) {
  console.log(
    "Connection check failed:",
    error instanceof Error ? error.message : "Unknown error"
  );

  process.exit(1);
}