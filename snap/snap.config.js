module.exports = {
  bundler: 'webpack',
  input: 'src/index.js',
  output: {
    path: 'dist',
    filename: 'bundle.js',
  },
  server: {
    port: 8081,
  },

  // ✅ 추가 1) manifest 업데이트(= build 시 shasum 자동 갱신)
  manifest: {
    update: true,
  },

  // ✅ 추가 2) Buffer 등 Node built-in polyfill
  polyfills: {
    buffer: true,
  },

  // (선택) 경고 숨기고 싶으면
  // stats: { buffer: false, builtIns: false },
};
