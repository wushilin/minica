const PROXY_CONFIG = [
  {
    context: [
    		 "/ca/"
    ],
    target: "http://localhost:9988/",
    changeOrigin: true,
    secure: false
  }
];

module.exports = PROXY_CONFIG;
