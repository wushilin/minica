const PROXY_CONFIG = [
  {
    context: [
    		 "/ca/"
    ],
    target: "http://localhost:8080/",
    changeOrigin: true,
    secure: false
  }
];

module.exports = PROXY_CONFIG;
