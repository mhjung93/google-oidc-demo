// Mode 3 Snap 빌드 설정 — Mode 2 snap/snap.config.js 와 같은 구성에 포트만 8082 다(Mode 2 는 8081).
// snap id 는 local:http://localhost:8082 이고, 에이전트 /wallet/config 가 페이지에 알려 준다.
// 이 파일은 @metamask/snaps-cli 가 직접 CommonJS 로 변환해 읽으므로 package.json 의 "type": "module" 과 무관하게 module.exports 를 쓴다.
module.exports = {
  bundler: 'webpack',
  input: 'src/index.js',
  output: {
    path: 'dist',
    filename: 'bundle.js',
  },
  server: {
    port: 8082,
  },
  // @metamask/snaps-sdk 가 Buffer 전역을 참조한다(우리 코드는 쓰지 않는다). Mode 2 snap/ 과 같이 polyfill 을 켜 둔다.
  polyfills: {
    buffer: true,
  },

  // 빌드마다 manifest 의 shasum 을 갱신한다.
  manifest: {
    update: true,
  },

  // package.json 의 "type": "module"(단위 테스트가 src/*.js 를 그대로 import 하려면 필요하다) 때문에 webpack 이
  // 소스를 ESM 으로 읽는다. 그러면 swc 가 CommonJS 로 바꾼 출력의 require() 를 webpack 이 해석하지 않아
  // 번들에 require("@metamask/snaps-sdk") 가 그대로 남고 SES 평가가 "require is not a function" 으로 죽는다.
  // 소스 규칙을 javascript/auto 로 되돌려 Mode 2 snap/ 과 같은 CommonJS 번들이 나오게 한다.
  customizeWebpackConfig: (config) => {
    for (const rule of config.module.rules) {
      if (rule && rule.use) rule.type = 'javascript/auto';
    }
    return config;
  },
};
