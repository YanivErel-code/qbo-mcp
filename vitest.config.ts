import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    setupFiles: ["./tests/setup.ts"],
    // Each test file is a separate worker; the in-memory SQLite is per-worker.
    // Within a file, individual tests share the DB and clear it via clearDb().
    include: ["src/**/*.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "html", "lcov"],
      include: ["src/**/*.ts"],
      exclude: [
        "src/**/*.test.ts",
        "src/index.ts",        // entry point, just calls listen()
        "tests/**",
      ],
      thresholds: {
        // Lines/functions/statements gate at 80% (comfortably above what we
        // currently hit) — these catch logic regressions reliably.
        // Branches at 65% — the difference is mostly HTML-template
        // permutations and disabled-CF-Access fallback paths, not core logic.
        lines: 80,
        functions: 80,
        branches: 65,
        statements: 80,
      },
    },
  },
});
