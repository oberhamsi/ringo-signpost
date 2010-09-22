var signpost = Packages.oauth.signpost;

/**
 * Create a oauth signing function that can be passed to ringo's httpclient as the
 * beforeSend parameter.
 *
 * @usage
 *   var oAuthRequestSigner = createRequestSigner(
 *          {accessToken: 'xxxx', tokenSecret:'xxxx'},
 *
 *          {consumer: {
 *              key: 'xxxx',
 *              secret: 'xxxx',
 *            }
 *          }
 * );
 *   var response = require('ringo/httpclient').request({
 *       url: "http://example.com/oauth/protected/",
 *       beforeSend: oAuthRequestSigner
 *   });
 *
 *
 * @param {Object} userToken object with `accessToken` and `tokenSecret` properties.
 *                  The object created at req.session.oAuthToken by ringo-signpost
 *                  middleware can be passed.
 * @param {Object} oAuthConfig object with consumer.key and consumer.secret properties.
 *                             The object used for instantiating ringo-signpost
 *                             middleware can be passed.
 *
 */
exports.createRequestSigner = function(userToken, oAuthConfig) {
    if (!userToken.accessToken || !userToken.tokenSecret) {
        throw new Error('Missing user access token');
    }
    if (!oAuthConfig.consumer.key || !oAuthConfig.consumer.secret) {
        throw new Error('Missing consumer token');
    }
    var consumer = new signpost.jetty.JettyOAuthConsumer(oAuthConfig.consumer.key, oAuthConfig.consumer.secret);
    consumer.setTokenWithSecret(userToken.accessToken, userToken.tokenSecret);
    
    return function(exchange) {
        consumer.sign(exchange.contentExchange);
    }
};
