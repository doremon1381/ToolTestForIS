// Copyright 2016 Google Inc.
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
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Policy;
using System.Xml;
using System.Runtime.Remoting.Contexts;

namespace OAuthApp
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        // client configuration
        // TODO: google
        const string google_clientSecret = "";
        const string google_clientId = "";
        const string google_authorizationEndpoint = "https://accounts.google.com/o/oauth2/auth";
        const string google_tokenEndpoint = "https://oauth2.googleapis.com/token";
        const string google_userInfoEndpoint = "https://www.googleapis.com/oauth2/userinfo";
        // TODO: for my identity client
        const string clientId = "PrintingManagermentServer";
        const string clientSecret = "actR0Gt/JIBPnujIpTA0PDmD1IcBzeSMrWSxVy8XmLQ=";
        const string authorizationEndpoint = "https://localhost:7180/oauth2/authorize";
        const string tokenEndpoint = "https://localhost:7180/oauth2/token";
        const string userInfoEndpoint = "https://localhost:7180/oauth2/userinfo";
        // TODO: add redirect_uri for now, but it need to change when for particular client in identity server,
        //     : this is used, for example, for redirect after getting access token from identity server, to client, and after that client will exchange access token for token by itself
        //     : by intend, this uri will be use in 302 response, but in this situation, we catch the response and handle redrirecting, so for now this string only need to check following oauth requirement
        const string redirectUri = "http://localhost:59867";

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
            //var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var port = 59867;
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
            output("redirect URI: " + redirectURI);

            // Creates an HttpListener to listen for requests on that redirect URI.
            var http = new HttpListener();
            http.Prefixes.Add(redirectURI);
            output("Listening..");
            http.Start();

            string nonce = randomDataBase64url(32);
            // Creates the OAuth 2.0 authorization request.
            string authorizationRequest = string.Format("{0}?response_type=code&scope=openid%20profile%20email&redirect_uri={1}&client_id={2}&state={3}&code_challenge={4}&code_challenge_method={5}&nonce={6}",
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

            output("Google request: " + authorizationEndpoint);
            output("scope=openid%20profile%20email");
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
                output(String.Format("OAuth authorization error: {0}.", context.Request.QueryString.Get("error")));
                return;
            }
            if (context.Request.QueryString.Get("code") == null
                || context.Request.QueryString.Get("state") == null)
            {
                output("Malformed authorization response. " + context.Request.QueryString);
                return;
            }

            // extracts the code
            var code = context.Request.QueryString.Get("code");
            var incoming_state = context.Request.QueryString.Get("state");
            var scope = context.Request.QueryString.Get("scope");
            var authUser = context.Request.QueryString.Get("authuser");
            var promt = context.Request.QueryString.Get("prompt");

            // Compares the receieved state to the expected value, to ensure that
            // this app made the request which resulted in authorization.
            if (incoming_state != state)
            {
                output(String.Format("Received request with invalid state ({0})", incoming_state));
                return;
            }
            output("Authorization code: " + code);

            // Starts the code exchange at the Token Endpoint.
            performCodeExchange(code, code_verifier, redirectURI);
        }

        /// <summary>
        /// redirect uri is callback api that identityserver's response will go after received in user-agent
        /// for now, to test, I just use local http address
        /// </summary>
        /// <param name="code"></param>
        /// <param name="code_verifier"></param>
        /// <param name="redirectURI"></param>
        async void performCodeExchange(string code, string code_verifier, string redirectURI)
        {
            output("Exchanging code for tokens...");

            string state = randomDataBase64url(32);
            // builds the  request
            //string tokenRequestURI = "https://www.googleapis.com/oauth2/v4/token";
            string tokenRequestURI = "https://localhost:7180/oauth2/authentication/google";

            // sends the request
            // TODO: need to send state, but I ignore that step for now
            HttpWebRequest tokenRequest = (HttpWebRequest)WebRequest.Create($"{tokenRequestURI}?code={code}&state={state}");
            //tokenRequest.Method = "POST";
            tokenRequest.Method = "GET";
            tokenRequest.ContentType = "application/x-www-form-urlencoded";
            tokenRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
            tokenRequest.Headers.Add(string.Format("code_verifier:{0}", code_verifier));
            tokenRequest.Headers.Add(string.Format("redirect_uri:{0}", System.Uri.EscapeDataString(redirectURI)));

            try
            {
                // gets the response
                WebResponse tokenResponse = await tokenRequest.GetResponseAsync();

                string id_token = "";

                output("Request: " + tokenRequestURI);
                output("Method: " + tokenRequest.Method);
                //output("Header: code :" + tokenRequest.Headers["code"].ToString());
                output("Header: code_verifier :" + tokenRequest.Headers["code_verifier"].ToString());

                using (StreamReader reader = new StreamReader(tokenResponse.GetResponseStream()))
                {
                    // reads response body
                    string responseText = await reader.ReadToEndAsync();
                    output("user_info: " + responseText);
                }

            }
            catch (WebException ex)
            {
                if (ex.Status == WebExceptionStatus.ProtocolError)
                {
                    var response = ex.Response as HttpWebResponse;
                    if (response != null)
                    {
                        output("HTTP: " + response.StatusCode);
                        using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                        {
                            // reads response body
                            string responseText = await reader.ReadToEndAsync();
                            output(responseText);
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
            output("Making API Call to Userinfo...");

            // builds the  request
            string userinfoRequestURI = "https://www.googleapis.com/oauth2/v3/userinfo";

            // sends the request
            HttpWebRequest userinfoRequest = (HttpWebRequest)WebRequest.Create(userinfoRequestURI);
            userinfoRequest.Method = "GET";
            userinfoRequest.Headers.Add(string.Format("Authorization: Bearer {0}", access_token));
            userinfoRequest.ContentType = "application/x-www-form-urlencoded";
            userinfoRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

            // gets the response
            WebResponse userinfoResponse = await userinfoRequest.GetResponseAsync();
            using (StreamReader userinfoResponseReader = new StreamReader(userinfoResponse.GetResponseStream()))
            {
                // reads response body
                string userinfoResponseText = await userinfoResponseReader.ReadToEndAsync();
                output(userinfoResponseText);
            }

        }

        /// <summary>
        /// Appends the given string to the on-screen log, and the debug console.
        /// </summary>
        /// <param name="output">string to be appended</param>
        public void output(string output)
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

        private async void AuthorizationCodeFlow(object sender, RoutedEventArgs e)
        {
            // Generates state and PKCE values.
            string state = randomDataBase64url(32);
            string nonce = randomDataBase64url(32);
            string code_verifier = randomDataBase64url(32);
            string code_challenge = base64urlencodeNoPadding(sha256(code_verifier));
            const string code_challenge_method = "S256";
            var base64Authentication = Base64Encode(string.Format("{0}:{1}", this.UserName.Text, this.Password.Text));

            // Creates the OAuth 2.0 authorization request.
            string authorizationRequest = string.Format("{0}?response_type=code&scope=openid%20profile%20email%20offline_access&redirect_uri={1}&client_id={2}&state={3}&code_challenge={4}&code_challenge_method={5}&nonce={6}",
                authorizationEndpoint,
                System.Uri.EscapeDataString(redirectUri),
                clientId,
                state,
                code_challenge,
                code_challenge_method,
                nonce);

            output("Send request to web server: " + authorizationEndpoint);

            HttpWebRequest testRequest = (HttpWebRequest)WebRequest.Create(authorizationRequest);
            testRequest.Method = "GET";
            testRequest.Headers.Add(string.Format("Authorization: Basic {0}", base64Authentication));
            testRequest.ContentType = "application/x-www-form-urlencoded";
            testRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*;q=0.8";
            string authorizationCode = "";
            string incomingState = "";
            try
            {
                // gets the response
                WebResponse tokenResponse = await testRequest.GetResponseAsync();

                using (StreamReader reader = new StreamReader(tokenResponse.GetResponseStream()))
                {
                    // reads response body
                    var temp = await reader.ReadToEndAsync();
                    var sr = JsonConvert.DeserializeObject<Dictionary<string, string>>(temp);
                    authorizationCode = sr["code"];
                    incomingState = sr["state"];
                    output("user_info: " + authorizationCode);
                }
            }
            catch (WebException ex)
            {
                output(ex.Message);
                if (ex.Status == WebExceptionStatus.ProtocolError)
                {
                    //var response = ex.Response as HttpWebResponse;
                    //if (response != null)
                    //{
                    //    output("HTTP: " + response.StatusCode);
                    //    using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                    //    {
                    //        // reads response body
                    //        string error = await reader.ReadToEndAsync();
                    //        output(error);
                    //    }
                    //}

                }
                return;
            }

            if (incomingState != state)
            {
                output("state is not the same!");
                return;
            }

            output("For test, handle redirect");
            if (!string.IsNullOrEmpty(this.UserName.Text) &&
                !string.IsNullOrEmpty(this.Password.Text))
            {
                // Starts the code exchange at the Token Endpoint.
                // TODO: nonce will be received from web server, along with location uri, redirect uri
                nonce = randomDataBase64url(32);
                string state1 = randomDataBase64url(32);

                //basicAuthentication("https://localhost:7180/oauth2/authorize", clientId, redirectUri, state, nonce);
                AuthenticationWithCode(authorizationCode, code_verifier, state1);
            }
        }

        private async void AuthenticationWithCode(string authorizationCode, string codeVerifier, string state)
        {
            try
            {
                string tokenEndpointBody = string.Format("code={0}&client_id={1}&client_secret={2}&audience={3}&grant_type=authorization_code&redirect_uri={4}&code_verifier={5}&state={6}&scope="
                    , authorizationCode, clientId, clientSecret, "http://localhost:7209", redirectUri, codeVerifier, state);

                // TODO: send to identityserver to get id token and access token
                HttpWebRequest tokenRequest = (HttpWebRequest)WebRequest.Create(tokenEndpoint);
                tokenRequest.Method = "POST";
                tokenRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
                byte[] _byteVersion = Encoding.ASCII.GetBytes(tokenEndpointBody);
                tokenRequest.ContentLength = _byteVersion.Length;
                Stream stream = tokenRequest.GetRequestStream();
                await stream.WriteAsync(_byteVersion, 0, _byteVersion.Length);
                stream.Close();

                string accessToken = "";
                string idToken = "";
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
                }

                output("id_token" + idToken);

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
                    output("user_info" + userinfoResponseText);
                }
            }
            catch (Exception ex)
            {
                output(ex.Message);
                //throw;
            }
        }


        public static string Base64Encode(string userNamePassword)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(userNamePassword);
            return System.Convert.ToBase64String(plainTextBytes);
        }

        private async void Register(object sender, RoutedEventArgs e)
        {
            string register_uri = authorizationEndpoint;
            output("Send request to web server: " + register_uri);

            if (!string.IsNullOrEmpty(this.UserName.Text) &&
                !string.IsNullOrEmpty(this.Password.Text))
            {
                RegisterNewUser(register_uri);
            }
        }


        private async void RegisterNewUser(string registerUserRequestUri)
        {
            try
            {
                output("Making API Call to Register new user...");

                string state = randomDataBase64url(32);
                var base64Authentication = Base64Encode(string.Format("{0}:{1}", this.UserName.Text, this.Password.Text));
                // TODO: current role is not for identity server
                //var defaultRole = "admin,leader";

                // sends the request
                HttpWebRequest registerRequest = (HttpWebRequest)WebRequest.Create(string.Format("{0}?prompt=create", registerUserRequestUri));
                registerRequest.Method = "GET";
                registerRequest.Headers.Add(string.Format("Authorization: Basic {0}", base64Authentication));
                registerRequest.Headers.Add(string.Format("Email: {0}", this.Email.Text));
                registerRequest.ContentType = "application/x-www-form-urlencoded";
                registerRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*;q=0.8";

                output("Request: " + registerUserRequestUri);
                output("Method: " + registerRequest.Method);

                // gets the response
                WebResponse userinfoResponse = await registerRequest.GetResponseAsync();
                using (StreamReader userinfoResponseReader = new StreamReader(userinfoResponse.GetResponseStream()))
                {
                    // reads response body
                    string userinfoResponseText = await userinfoResponseReader.ReadToEndAsync();
                    output(userinfoResponseText);
                }

            }
            catch (Exception ex)
            {
                output(ex.Message);
            }

        }

        private void ChangePassword(object sender, RoutedEventArgs e)
        {

        }
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
