const PROXY_CONFIG = [
  {
    context: [
    		 "/ca/"
    ],
    target: "http://192.168.44.101:9988/",
    changeOrigin: true,
    secure: false
  }
];

module.exports = PROXY_CONFIG;
