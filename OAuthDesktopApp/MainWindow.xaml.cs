﻿// Copyright 2016 Google Inc.
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Windows;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Web;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text.Json.Serialization;

namespace OAuthApp
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        // client configuration
        // TODO: google
        //const string google_clientSecret = "";
        const string google_clientId = "558160357396-q5qp0ppf4r5svc0g0smshfs8cdcffkm3.apps.googleusercontent.com";
        const string google_authorizationEndpoint = "https://accounts.google.com/o/oauth2/auth";
        const string google_tokenEndpoint = "https://oauth2.googleapis.com/token";
        const string google_userInfoEndpoint = "https://www.googleapis.com/oauth2/userinfo";
        // TODO: for my identity client
        const string clientId = "ManagermentServer";
        const string clientSecret = "actR0Gt/JIBPnujIpTA0PDmD1IcBzeSMrWSxVy8XmLQ=";
        const string authorizationEndpoint = "https://localhost:7180/oauth2/authorize";
        const string registerEndpoint = "https://localhost:7180/auth/register";
        const string tokenEndpoint = "https://localhost:7180/oauth2/token";
        const string userInfoEndpoint = "https://localhost:7180/oauth2/userinfo";
        const string jwks_uri = "https://localhost:7180/oauth2/jwks";
        // TODO: add redirect_uri for now, but it need to change when for particular client in identity server,
        //     : this is used, for example, for redirect after getting access token from identity server, to client, and after that client will exchange access token for token by itself
        //     : by intend, this uri will be use in 302 response, but in this situation, we catch the response and handle redrirecting, so for now this string only need to check following oauth requirement
        const string redirectUri = "http://127.0.0.1/login";

        private string _id_token = "";

        public MainWindow()
        {
            InitializeComponent();
        }

        // ref http://stackoverflow.com/a/3978040
        public static int GetRandomUnusedPort()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            //var port = 59867;
            listener.Stop();
            return port;
        }

        private async void button_Click(object sender, RoutedEventArgs e)
        {
            // Generates state and PKCE values.
            string state = randomDataBase64url(32);
            string code_verifier = randomDataBase64url(32);
            string code_challenge = base64urlencodeNoPadding(sha256(code_verifier));
            const string code_challenge_method = "S256";

            // Creates a redirect URI using an available port on the loopback address.
            string redirectURI = string.Format("http://{0}:{1}/", IPAddress.Loopback, GetRandomUnusedPort());
            //string redirectURI1 = string.Format("http://localhost:5173/call-back");
            Output("redirect URI: " + redirectURI);

            // Creates an HttpListener to listen for requests on that redirect URI.
            var http = new HttpListener();
            http.Prefixes.Add(redirectURI);
            Output("Listening..");
            http.Start();

            string nonce = randomDataBase64url(32);
            // Creates the OAuth 2.0 authorization request.
            string authorizationRequest = string.Format("{0}?response_type=code&scope=openid%20profile%20email&redirect_uri={1}&client_id={2}&state={3}&code_challenge={4}&code_challenge_method={5}&nonce={6}&access_type=offline",
                google_authorizationEndpoint,
                System.Uri.EscapeDataString(redirectURI),
                google_clientId,
                state,
                code_challenge,
                code_challenge_method,
                nonce);
            // TODO: try to use implicit grant with google, but not yet success
            //string authorizationRequest = string.Format("{0}?response_type=token&scope=openid%20profile%20email&redirect_uri={1}&client_id={2}&state={3}",
            //    authorizationEndpoint,
            //    System.Uri.EscapeDataString(redirectURI),
            //    clientID,
            //    state);

            Output("Google request: " + google_authorizationEndpoint);
            //output("scope=openid%20profile%20email");
            // Opens request in the browser.
            System.Diagnostics.Process.Start(authorizationRequest);
            // Waits for the OAuth authorization response.
            var context = await http.GetContextAsync();

            // Brings this app back to the foreground.
            this.Activate();

            // Sends an HTTP response to the browser.
            var response = context.Response;

            string responseString = string.Format("<html><head><meta http-equiv='refresh' content='10;url=https://google.com'></head><body>Please return to the app.</body></html>");
            var buffer = System.Text.Encoding.UTF8.GetBytes(responseString);
            response.ContentLength64 = buffer.Length;
            var responseOutput = response.OutputStream;
            Task responseTask = responseOutput.WriteAsync(buffer, 0, buffer.Length).ContinueWith((task) =>
            {
                responseOutput.Close();
                http.Stop();
                Console.WriteLine("HTTP server stopped.");
            });

            // Checks for errors.
            if (context.Request.QueryString.Get("error") != null)
            {
                Output(String.Format("OAuth authorization error: {0}.", context.Request.QueryString.Get("error")));
                return;
            }
            if (context.Request.QueryString.Get("code") == null
                || context.Request.QueryString.Get("state") == null)
            {
                Output("Malformed authorization response. " + context.Request.QueryString);
                return;
            }

            // extracts the code
            var sr = context.Request.QueryString.ToString();
            var code = context.Request.QueryString.Get("code");
            var incoming_state = context.Request.QueryString.Get("state");
            var scope = context.Request.QueryString.Get("scope");
            var authUser = context.Request.QueryString.Get("authuser");
            var promt = context.Request.QueryString.Get("prompt");

            // Compares the receieved state to the expected value, to ensure that
            // this app made the request which resulted in authorization.
            if (incoming_state != state)
            {
                Output(String.Format("Received request with invalid state ({0})", incoming_state));
                return;
            }
            Output("Authorization code: " + code);

            // Starts the code exchange at the Token Endpoint.
            performCodeExchange(code, code_verifier, redirectURI, nonce);
        }

        /// <summary>
        /// redirect uri is callback api that identityserver's response will go after received in user-agent
        /// for now, to test, I just use local http address
        /// </summary>
        /// <param name="code"></param>
        /// <param name="code_verifier"></param>
        /// <param name="redirectURI"></param>
        async void performCodeExchange(string code, string code_verifier, string redirectURI, string nonce)
        {
            Output("Exchanging code for tokens...");

            string state = randomDataBase64url(32);
            // builds the  request
            //string tokenRequestURI = "https://www.googleapis.com/oauth2/v4/token";
            string tokenRequestURI = "https://localhost:7180/oauth2/authorize/google";
            string redirectUri = System.Uri.EscapeDataString(redirectURI);

            string requestBody = $"code={code}&state={state}&client_id={clientId}&grant_type=authorization_code&code_verifier={code_verifier}&redirect_uri={redirectUri}&nonce={nonce}";
            // sends the request
            // TODO: need to send state, but I ignore that step for now
            HttpWebRequest tokenRequest = (HttpWebRequest)WebRequest.Create($"{tokenRequestURI}");
            tokenRequest.Method = "POST";
            //tokenRequest.Method = "GET";
            tokenRequest.ContentType = "application/x-www-form-urlencoded";
            tokenRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
            byte[] _byteVersion = Encoding.ASCII.GetBytes(requestBody);
            tokenRequest.ContentLength = _byteVersion.Length;
            Stream stream = tokenRequest.GetRequestStream();
            await stream.WriteAsync(_byteVersion, 0, _byteVersion.Length);
            stream.Close();

            try
            {
                // gets the response
                WebResponse tokenResponse = await tokenRequest.GetResponseAsync();

                string id_token = "";

                Output("Request: " + tokenRequestURI);
                Output("Method: " + tokenRequest.Method);
                //output("Header: code :" + tokenRequest.Headers["code"].ToString());
                //output("Header: code_verifier :" + tokenRequest.Headers["code_verifier"].ToString());

                using (StreamReader reader = new StreamReader(tokenResponse.GetResponseStream()))
                {
                    // reads response body
                    string responseText = await reader.ReadToEndAsync();
                    Output("user_info: " + JsonConvert.SerializeObject(responseText));
                }

                //RefershAccessToken(refreshToken)

            }
            catch (WebException ex)
            {
                if (ex.Status == WebExceptionStatus.ProtocolError)
                {
                    var response = ex.Response as HttpWebResponse;
                    if (response != null)
                    {
                        Output("HTTP: " + response.StatusCode);
                        using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                        {
                            // reads response body
                            string responseText = await reader.ReadToEndAsync();
                            Output(responseText);
                        }
                    }

                }
            }
        }

        //static readonly char[] padding = { '=' };
        //private static string CreateGoogleAtHash(string accessToken)
        //{
        //    using (SHA256 sha256Hash = SHA256.Create())
        //    {
        //        byte[] bytes = sha256Hash.ComputeHash(Encoding.ASCII.GetBytes(accessToken));
        //        byte[] firstHalf = bytes.Take(bytes.Length / 2).ToArray();

        //        return System.Convert.ToBase64String(firstHalf).TrimEnd(padding).Replace('+', '-').Replace('/', '_');
        //    }
        //}

        async void userinfoCall(string access_token)
        {
            Output("Making API Call to Userinfo...");

            // builds the  request
            string userinfoRequestURI = "https://www.googleapis.com/oauth2/v3/userinfo";

            // sends the request
            HttpWebRequest userinfoRequest = (HttpWebRequest)WebRequest.Create(userinfoRequestURI);
            userinfoRequest.Method = "GET";
            userinfoRequest.Headers.Add(string.Format("Authorization: Bearer {0}", access_token));
            userinfoRequest.ContentType = "application/x-www-form-urlencoded";
            userinfoRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*;q=0.8";

            // gets the response
            WebResponse userinfoResponse = await userinfoRequest.GetResponseAsync();
            using (StreamReader userinfoResponseReader = new StreamReader(userinfoResponse.GetResponseStream()))
            {
                // reads response body
                string userinfoResponseText = await userinfoResponseReader.ReadToEndAsync();
                Output(userinfoResponseText);
            }

        }

        /// <summary>
        /// Appends the given string to the on-screen log, and the debug console.
        /// </summary>
        /// <param name="output">string to be appended</param>
        public void Output(string output)
        {
            textBoxOutput.Text = textBoxOutput.Text + output + Environment.NewLine;
            Console.WriteLine(output);
        }

        #region manipulate string
        /// <summary>
        /// Returns URI-safe data with a given input length.
        /// </summary>
        /// <param name="length">Input length (nb. output will be longer)</param>
        /// <returns></returns>
        public static string randomDataBase64url(uint length)
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] bytes = new byte[length];
            rng.GetBytes(bytes);
            return base64urlencodeNoPadding(bytes);
        }

        /// <summary>
        /// Returns the SHA256 hash of the input string.
        /// </summary>
        /// <param name="inputStirng"></param>
        /// <returns></returns>
        public static byte[] sha256(string inputStirng)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(inputStirng);
            SHA256Managed sha256 = new SHA256Managed();
            return sha256.ComputeHash(bytes);
        }

        /// <summary>
        /// Base64url no-padding encodes the given input buffer.
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
        public static string base64urlencodeNoPadding(byte[] buffer)
        {
            string base64 = Convert.ToBase64String(buffer);

            // Converts base64 to base64url.
            base64 = base64.Replace("+", "-");
            base64 = base64.Replace("/", "_");
            // Strips padding.
            base64 = base64.Replace("=", "");

            return base64;
        }
        #endregion

        private HttpListener currentHttpListener;
        private HttpListener GetListenerWithSpecificPort(string redirectURI)
        {
            if (currentHttpListener == null)
            {
                currentHttpListener = new HttpListener();
                currentHttpListener.Prefixes.Add(redirectURI);
            }

            return currentHttpListener;
        }

        private async void AuthorizationCodeFlow(object sender, RoutedEventArgs e)
        {
            HttpListener currentHttpListener = null;
            try
            {
                // Generates state and PKCE values.
                string state = randomDataBase64url(32);
                string nonce = randomDataBase64url(32);
                string code_verifier = randomDataBase64url(32);
                string code_challenge = base64urlencodeNoPadding(sha256(code_verifier));
                const string code_challenge_method = "S256";
                var base64Authentication = Base64Encode(string.Format("{0}:{1}", this.UserName.Text, this.Password.Text));

                string redirectURI = string.Format("http://{0}:{1}/login/", IPAddress.Loopback, 59867);

                // Creates the OAuth 2.0 authorization request.
                string authorizationRequest = string.Format("{0}?resPonse_type=code&scope=openid%20profile%20email%20offline_access&redirect_uri={1}&client_id={2}&state={3}&code_challenge={4}&code_challenge_method={5}&nonce={6}&prompt={7}",
                    authorizationEndpoint,
                    System.Uri.EscapeDataString(redirectURI),
                    clientId,
                    state,
                    code_challenge,
                    code_challenge_method,
                    nonce,
                    "consent");

                // Creates an HttpListener to listen for requests on that redirect URI.
                currentHttpListener = GetListenerWithSpecificPort(redirectURI);
                Output("Listening..");
                currentHttpListener.Start();

                Output("Send request to web server: " + authorizationEndpoint);

                // Opens request in the browser.
                System.Diagnostics.Process.Start(authorizationRequest);
                // Waits for the OAuth authorization response.
                var context = await currentHttpListener.GetContextAsync();

                // Brings this app back to the foreground.
                this.Activate();

                // Sends an HTTP response to the browser.
                var response = context.Response;

                var responseOutput = response.OutputStream;
                Task responseTask = Task.Run(() =>
                {
                    responseOutput.Close();
                    //currentHttpListener.Stop();
                    //Console.WriteLine("HTTP server stopped.");
                });

                // Checks for errors.
                if (context.Request.QueryString.Get("error") != null)
                {
                    Output(String.Format("OAuth authorization error: {0}.", context.Request.QueryString.Get("error")));
                    return;
                }
                if (context.Request.QueryString.Get("code") == null
                    || context.Request.QueryString.Get("state") == null)
                {
                    Output("Malformed authorization response. " + context.Request.QueryString);
                    return;
                }

                // extracts the code
                var sr = context.Request.QueryString.ToString();
                var authorizationCode = context.Request.QueryString.Get("code");
                var incoming_state = context.Request.QueryString.Get("state");
                var scope = context.Request.QueryString.Get("scope");
                var authUser = context.Request.QueryString.Get("authuser");
                var promt = context.Request.QueryString.Get("prompt");

                if (incoming_state != state)
                {
                    Output("state is not the same!");
                    return;
                }

                Output("For test, handle redirect");
                if (!string.IsNullOrEmpty(this.UserName.Text) &&
                    !string.IsNullOrEmpty(this.Password.Text))
                {
                    // Starts the code exchange at the Token Endpoint.
                    // TODO: nonce will be received from web server, along with location uri, redirect uri
                    //nonce = randomDataBase64url(32);
                    //string state1 = randomDataBase64url(32);

                    //basicAuthentication("https://localhost:7180/oauth2/authorize", clientId, redirectUri, state, nonce);
                    await AuthenticationWithCode(authorizationCode, code_verifier, redirectURI);
                }
            }
            catch (Exception ex)
            {
                Output($"error: {ex.Message}");
            }
            finally
            {
                currentHttpListener.Stop();
                Console.WriteLine("HTTP server stopped.");
            }            
        }

        private async Task AuthenticationWithCode(string authorizationCode, string codeVerifier, string redirectURI)
        {
            try
            {
                string tokenEndpointBody = string.Format("code={0}&client_id={1}&client_secret={2}&audience={3}&grant_type=authorization_code&redirect_uri={4}&code_verifier={5}&scope="
                    , authorizationCode, clientId, clientSecret, "http://localhost:7209", redirectURI, codeVerifier);

                // TODO: send to identityserver to get id token and access token
                HttpWebRequest tokenRequest = (HttpWebRequest)WebRequest.Create(tokenEndpoint);
                tokenRequest.Method = "POST";
                tokenRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*;q=0.8";
                byte[] _byteVersion = Encoding.ASCII.GetBytes(tokenEndpointBody);
                tokenRequest.ContentLength = _byteVersion.Length;
                Stream stream = tokenRequest.GetRequestStream();
                await stream.WriteAsync(_byteVersion, 0, _byteVersion.Length);
                stream.Close();

                string accessToken = "";
                string idToken = "";
                string refreshToken = "";
                string publicKeyStr = null;
                // TODO:  exchange for user_info
                //     : check in web db user token by user name or email
                //     : if do not have one, create one for new user_info
                //     : save loginSession draft - save session that was success

                WebResponse serverResponse = await tokenRequest.GetResponseAsync();
                using (StreamReader reader = new StreamReader(serverResponse.GetResponseStream()))
                {
                    // reads response body
                    var temp = await reader.ReadToEndAsync();

                    var sr = JsonConvert.DeserializeObject<Dictionary<string, string>>(temp);
                    accessToken = sr["access_token"];
                    idToken = sr["id_token"];
                    refreshToken = sr["refresh_token"];
                }

                //output("access_token: " + accessToken);
                //output("id_token: " + idToken);

                var publicKey = await JsonToRSAPublicKey(publicKeyStr);
                var isIdTokenValidate = VeriryJwtSignature(publicKey, idToken);

                // sends the request
                HttpWebRequest userinfoRequest = (HttpWebRequest)WebRequest.Create(userInfoEndpoint);
                userinfoRequest.Method = "GET";
                userinfoRequest.Headers.Add(string.Format("Authorization: Bearer {0}", accessToken));
                userinfoRequest.ContentType = "application/x-www-form-urlencoded";
                userinfoRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

                // gets the response
                WebResponse userinfoResponse = await userinfoRequest.GetResponseAsync();
                using (StreamReader userinfoResponseReader = new StreamReader(userinfoResponse.GetResponseStream()))
                {
                    // reads response body
                    string userinfoResponseText = await userinfoResponseReader.ReadToEndAsync();
                    //output(userinfoResponseText);
                    Output("user_info" + userinfoResponseText);
                }

                //output("refresh access Token");
                await RefershAccessToken(refreshToken);
            }
            catch (WebException ex)
            {
                if (ex.Status == WebExceptionStatus.ProtocolError)
                {
                    var response = ex.Response as HttpWebResponse;
                    if (response != null)
                    {
                        Output("HTTP: " + response.StatusCode);
                        using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                        {
                            // reads response body
                            string responseText = await reader.ReadToEndAsync();
                            var details = JsonConvert.DeserializeObject<ProblemDetails>(responseText);
                            Output("error: " + $"status: {details.Status}; message: {details.Detail}");
                        }
                    }

                }
            }
            catch (Exception ex)
            {
                Output("error" + ex.Message);
            }
        }

        private async Task RefershAccessToken(string refreshToken)
        {
            string refreshAccessTokenBody = string.Format("client_id={0}&client_secret={1}&audience={2}&refresh_token={3}&grant_type=refresh_token&scope=openid%20profile"
                , clientId, clientSecret, "http://localhost:7209", refreshToken);

            HttpWebRequest refreshAccessToken = (HttpWebRequest)WebRequest.Create(tokenEndpoint);
            refreshAccessToken.Method = "POST";
            //refreshAccessToken.Headers.Add();
            refreshAccessToken.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
            byte[] _byteVersion = Encoding.ASCII.GetBytes(refreshAccessTokenBody);
            refreshAccessToken.ContentLength = _byteVersion.Length;
            Stream stream = refreshAccessToken.GetRequestStream();
            await stream.WriteAsync(_byteVersion, 0, _byteVersion.Length);
            stream.Close();

            WebResponse serverResponse = await refreshAccessToken.GetResponseAsync();
            using (StreamReader reader = new StreamReader(serverResponse.GetResponseStream()))
            {
                // reads response body
                var temp = await reader.ReadToEndAsync();

                //var sr = JsonConvert.DeserializeObject<Dictionary<string, string>>(temp);
                Output("refresh access token result: " + temp);
            }
        }

        public async Task<RSAParameters> JsonToRSAPublicKey(string publicKeyStr)
        {
            // sends the request
            HttpWebRequest publicKeyRequest = (HttpWebRequest)WebRequest.Create(jwks_uri);
            publicKeyRequest.Method = "GET";
            //userinfoRequest.Headers.Add(string.Format("Authorization: Bearer {0}", accessToken));
            publicKeyRequest.ContentType = "application/x-www-form-urlencoded";
            publicKeyRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

            string publicKey = "";
            // gets the response
            WebResponse userinfoResponse = await publicKeyRequest.GetResponseAsync();
            using (StreamReader userinfoResponseReader = new StreamReader(userinfoResponse.GetResponseStream()))
            {
                // reads response body
                publicKey = await userinfoResponseReader.ReadToEndAsync();
                //output(userinfoResponseText);
                //output("user_info" + userinfoResponseText);
            }

            return JsonConvert.DeserializeObject<RSAParameters>(publicKey);
        }

        public bool VeriryJwtSignature(RSAParameters publicKey, string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            // Verify JWT signature
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new RsaSecurityKey(publicKey),
                ValidateIssuer = false, // Customize as needed
                ValidateAudience = false, // Customize as needed
            };

            ClaimsPrincipal userIdenttiy = null;

            try
            {
                userIdenttiy = tokenHandler.ValidateToken(token, validationParameters, out _);

            }
            catch (Exception ex)
            {
                Output(ex.Message);
                return false;
            }

            // 'claimsPrincipal' contains the validated claims
            return userIdenttiy.Claims.Count() > 0;
        }

        public static string Base64Encode(string userNamePassword)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(userNamePassword);
            return System.Convert.ToBase64String(plainTextBytes);
        }

        private async void Register(object sender, RoutedEventArgs e)
        {
            string register_uri = registerEndpoint;
            Output("Send request to web server: " + register_uri);

            if (!string.IsNullOrEmpty(this.UserName.Text)
                && !string.IsNullOrEmpty(this.Password.Text)
                && !string.IsNullOrEmpty(this.FirstName.Text)
                && !string.IsNullOrEmpty(this.Email.Text)
                && !string.IsNullOrEmpty(this.LastName.Text))
            {
                RegisterNewUser(register_uri);
            }
        }


        private async void RegisterNewUser(string registerUserRequestUri)
        {
            try
            {
                Output("Making API Call to Register new user...");

                string state = randomDataBase64url(32);
                var base64Authentication = Base64Encode(string.Format("{0}:{1}", this.UserName.Text, this.Password.Text));
                // TODO: current role is not for identity server
                //var defaultRole = "admin,leader";
                string requestQuery = string.Format(string.Format("{0}?state={1}&client_id={2}" +
                    "&email={3}&first_name={4}&last_name={5}&gender={6}",
                    registerUserRequestUri, state, clientId, this.Email.Text, HttpUtility.UrlEncode(this.FirstName.Text.TrimStart().TrimEnd()), HttpUtility.UrlEncode(this.LastName.Text.TrimStart().TrimEnd()), "male"));

                // sends the request
                HttpWebRequest registerRequest = (HttpWebRequest)WebRequest.Create(requestQuery);
                registerRequest.Method = "POST";
                registerRequest.Headers.Add(string.Format("Register: Basic {0}", base64Authentication));
                registerRequest.Headers.Add(string.Format("Email: {0}", this.Email.Text));
                registerRequest.ContentType = "application/x-www-form-urlencoded";
                registerRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*;q=0.8";

                Output("Request: " + registerUserRequestUri);
                Output("Method: " + registerRequest.Method);

                // gets the response
                WebResponse userinfoResponse = await registerRequest.GetResponseAsync();
                using (StreamReader userinfoResponseReader = new StreamReader(userinfoResponse.GetResponseStream()))
                {
                    // reads response body
                    string userinfoResponseText = await userinfoResponseReader.ReadToEndAsync();
                    Output(userinfoResponseText);
                }

            }
            catch (Exception ex)
            {
                Output(ex.Message);
            }

        }

        private void ChangePassword(object sender, RoutedEventArgs e)
        {

        }
    }

    //
    // Summary:
    //     A machine-readable format for specifying errors in HTTP API responses based on
    //     https://tools.ietf.org/html/rfc7807.
    public class ProblemDetails
    {
        public ProblemDetails() { }

        //
        // Summary:
        //     A URI reference [RFC3986] that identifies the problem type. This specification
        //     encourages that, when dereferenced, it provide human-readable documentation for
        //     the problem type (e.g., using HTML [W3C.REC-html5-20141028]). When this member
        //     is not present, its value is assumed to be "about:blank".
        [System.Text.Json.Serialization.JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        [JsonPropertyName("type")]
        [JsonPropertyOrder(-5)]
        public string Type { get; set; }
        //
        // Summary:
        //     A short, human-readable summary of the problem type. It SHOULD NOT change from
        //     occurrence to occurrence of the problem, except for purposes of localization(e.g.,
        //     using proactive content negotiation; see[RFC7231], Section 3.4).
        [System.Text.Json.Serialization.JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        [JsonPropertyName("title")]
        [JsonPropertyOrder(-4)]
        public string Title { get; set; }
        //
        // Summary:
        //     The HTTP status code([RFC7231], Section 6) generated by the origin server for
        //     this occurrence of the problem.
        [System.Text.Json.Serialization.JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        [JsonPropertyName("status")]
        [JsonPropertyOrder(-3)]
        public int Status { get; set; }
        //
        // Summary:
        //     A human-readable explanation specific to this occurrence of the problem.
        [System.Text.Json.Serialization.JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        [JsonPropertyName("detail")]
        [JsonPropertyOrder(-2)]
        public string Detail { get; set; }
        //
        // Summary:
        //     A URI reference that identifies the specific occurrence of the problem. It may
        //     or may not yield further information if dereferenced.
        [System.Text.Json.Serialization.JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        [JsonPropertyName("instance")]
        [JsonPropertyOrder(-1)]
        public string Instance { get; set; }
        //
        // Summary:
        //     Gets the System.Collections.Generic.IDictionary`2 for extension members.
        //
        //     Problem type definitions MAY extend the problem details object with additional
        //     members. Extension members appear in the same namespace as other members of a
        //     problem type.
        //
        // Remarks:
        //     The round-tripping behavior for Microsoft.AspNetCore.Mvc.ProblemDetails.Extensions
        //     is determined by the implementation of the Input \ Output formatters. In particular,
        //     complex types or collection types may not round-trip to the original type when
        //     using the built-in JSON or XML formatters.
        [System.Text.Json.Serialization.JsonExtensionData]
        public IDictionary<string, object> Extensions { get; set; }
    }

    /// <summary>
    /// TODO: will delete
    /// </summary>
    public static class RNGCryptoServicesUltilities
    {
        // rfc 7636 impliment
        public static void GetMitigateAttackMethod()
        {
            string status = RandomStringGeneratingWithLength(32);
            string code_verifier = RandomStringGeneratingWithLength(32);
            string code_challenge = Base64UrlEncodeNoPadding(code_verifier.WithSHA265());
            string code_challenge_method = "S256";
        }

        public static string RandomStringGeneratingWithLength(int length)
        {
            RNGCryptoServiceProvider strGenerator = new RNGCryptoServiceProvider();
            byte[] arr = new byte[length];
            strGenerator.GetBytes(arr, 0, length);

            return Base64UrlEncodeNoPadding(arr);
        }

        private static string Base64UrlEncodeNoPadding(byte[] str)
        {
            string base64 = Convert.ToBase64String(str);

            // convert base64 to base64url
            base64.Replace("+", "-");
            base64.Replace("/", "_");

            // strip padding
            base64.Replace("=", "");

            return base64;
        }

        private static byte[] WithSHA265(this string str)
        {
            byte[] newByteArr = Encoding.ASCII.GetBytes(str);
            SHA256Managed sha256 = new SHA256Managed();
            return sha256.ComputeHash(newByteArr);
        }

        public static string GetStringWithSHA256(this string str)
        {
            byte[] newByteArr = Encoding.ASCII.GetBytes(str);
            SHA256Managed sha256 = new SHA256Managed();
            var hashBytes = sha256.ComputeHash(newByteArr);

            StringBuilder sb = new StringBuilder();

            foreach (var b in hashBytes)
            {
                sb.Append(b.ToString());
            }

            return sb.ToString();
        }
    }
}
