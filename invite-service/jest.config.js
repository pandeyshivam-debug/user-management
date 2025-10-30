export const preset = 'ts-jest';
export const testEnvironment = 'node';
export const roots = ['<rootDir>/src'];
export const setupFilesAfterEnv = ['<rootDir>/jest.setup.js'];
export const testMatch = ['**/*.test.ts'];
export const collectCoverage = true;
export const collectCoverageFrom = ['src/**/*.ts', '!src/**/*.d.ts', '!src/**/index.ts'];
export const coverageDirectory = 'coverage';  
export const moduleFileExtensions = ['ts', 'js', 'json', 'node'];
export const clearMocks = true;

export const reporters = [
  'default',
  ['jest-html-reporters', {
    publicPath: './coverage/test-report',
    filename: 'auth-report.html',
    pageTitle: 'Auth API Test Report',
    includeConsoleLog: true
  }]
];