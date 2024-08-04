import { defineConfig } from 'vitest/config'

export default defineConfig({
	test: {
		coverage: {
			provider: 'v8',
			include: ['src/**/*.mjs', 'src/**/*.mts'],
			exclude: ['src/**/tests/**/*', 'coverage/**/*'],
			thresholds: {
				statements: 90.0,
				branches: 90.0,
				functions: 85.0,
				lines: 90.0,
			},
			reportsDirectory: 'coverage',
		},
		include: ['src/**/tests/**/*.test.mts'],
	},
})
