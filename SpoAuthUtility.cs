/*  
    (c) Copyright 2014-2015 Fabio Cuneaz 

    This file is part of Cookie365.

    Cookie365 is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Cookie365 is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Cookie365.  If not, see <http://www.gnu.org/licenses/>.

*/

using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using System.Threading;
using System.Web.Script.Serialization;

namespace Cookie365
{
    internal class SamlSecurityToken
    {
        public byte[] Token
        {
            get;
            set;
        }

        public DateTime Expires
        {
            get;
            set;
        }
    }

    internal class SPOAuthCookies
    {
        public string FedAuth
        {
            get; set;
        }

        public string RtFA
        {
            get; set;
        }

        public Uri Host
        {
            get; set;
        }

        public DateTime Expires
        {
            get;
            set;
        }
    }
            
    internal class SpoAuthUtility
    {
        Uri spSiteUrl;
        string username;
        string password;
        Uri adfsIntegratedAuthUrl;
        Uri adfsAuthUrl;
        bool useIntegratedWindowsAuth;
        bool verbose;
        static SpoAuthUtility current;
        public CookieContainer cookieContainer;
        SamlSecurityToken stsAuthToken;

        const string msoStsUrl = "https://login.microsoftonline.com/extSTS.srf";
        const string msoLoginUrl = "https://login.microsoftonline.com/login.srf";
        const string msoHrdUrl = "https://login.microsoftonline.com/GetUserRealm.srf";
        const string wsse = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
        const string wsu = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
        const string wst = "http://schemas.xmlsoap.org/ws/2005/02/trust";
        const string saml ="urn:oasis:names:tc:SAML:1.0:assertion";
        const string spowssigninUri = "_forms/default.aspx?wa=wsignin1.0";

        public static async Task<bool> Create(Uri spSiteUrl, string username, string password, bool useIntegratedWindowsAuth, bool verbose)
        {
            var utility = new SpoAuthUtility(spSiteUrl, username, password, useIntegratedWindowsAuth,verbose);
            CookieContainer cc = await utility.GetCookieContainer();
            var cookies = from Cookie c in cc.GetCookies(spSiteUrl) where c.Name =="FedAuth" select c;
            if (cookies.Count() > 0)
            {
                current = utility;
                return true;
            }
            else
                throw new Exception("Could not retrieve Auth cookies");
        }

        private SpoAuthUtility(Uri spSiteUrl, string username, string password, bool useIntegratedWindowsAuth, bool verbose)
        {
            this.verbose = verbose; 
            this.spSiteUrl = spSiteUrl;
            this.username = username;
            this.password = password;
            this.useIntegratedWindowsAuth = useIntegratedWindowsAuth;
           
            stsAuthToken = new SamlSecurityToken();
        }

        public static SpoAuthUtility Current
        {
            get
            {
                return current;
            }
        }

        public Uri SiteUrl
        {
            get
            {
                return this.spSiteUrl;
            }
        }

        public async Task<CookieContainer> GetCookieContainer()
        {
            if (stsAuthToken != null)
            {
                if (DateTime.Now > stsAuthToken.Expires)
                {
                    this.stsAuthToken = await GetMsoStsSAMLToken();
                    SPOAuthCookies cookies = await GetSPOAuthCookies(this.stsAuthToken);
                    CookieContainer cc = new CookieContainer();

                    Cookie samlAuthCookie = new Cookie("FedAuth", cookies.FedAuth)
                    {
                        Path = "/",
                        Expires = this.stsAuthToken.Expires,
                        Secure = cookies.Host.Scheme.Equals("https"),
                        HttpOnly = true,
                        Domain = cookies.Host.Host
                    };

                    cc.Add(this.spSiteUrl, samlAuthCookie);
                    
                    Cookie rtFACookie = new Cookie("rtFA", cookies.RtFA)
                    {
                        Path = "/",
                        Expires = this.stsAuthToken.Expires,
                        Secure = cookies.Host.Scheme.Equals("https"),
                        HttpOnly = true,
                        Domain = cookies.Host.Host
                    };

                    cc.Add(this.spSiteUrl, rtFACookie);
                    
                    this.cookieContainer = cc;
                }
            }

            return this.cookieContainer;
        }

        private async Task<SPOAuthCookies> GetSPOAuthCookies(SamlSecurityToken stsToken)
        {
            // signs in to SPO with the security token issued by MSO STS and gets the fed auth cookies
            // the fed auth cookie needs to be attached to all SPO REST services requests
            Uri siteUri = this.spSiteUrl;
            Uri wsSigninUrl = new Uri(String.Format("{0}://{1}/{2}", siteUri.Scheme, siteUri.Authority, spowssigninUri));
            HttpClientHandler clientHandler;
            if (WebRequest.DefaultWebProxy.GetProxy(siteUri).ToString() != siteUri.ToString())
            {
                if (verbose) Console.WriteLine("Using proxy...[" + WebRequest.DefaultWebProxy.GetProxy(siteUri).ToString() + "]");
                clientHandler = new HttpClientHandler();
                WebProxy proxy = new WebProxy((WebRequest.DefaultWebProxy.GetProxy(siteUri)));
                proxy.Credentials = CredentialCache.DefaultCredentials;
                proxy.UseDefaultCredentials = true;
                clientHandler.UseCookies = true;
                clientHandler.UseProxy = true;
                clientHandler.Proxy = proxy;
            }
            else clientHandler = new HttpClientHandler();
            SPOAuthCookies spoAuthCookies = null;

            if (verbose) Console.Write("Retrieving Cookies....");
            try
            {
                await HttpUtility.SendHttpRequest(
                wsSigninUrl,
                HttpMethod.Post,
                new MemoryStream(stsToken.Token),
                "application/x-www-form-urlencoded",
                clientHandler);

                spoAuthCookies = new SPOAuthCookies();
           
                spoAuthCookies.FedAuth = clientHandler.CookieContainer.GetCookies(wsSigninUrl)["FedAuth"].Value;
                spoAuthCookies.RtFA = clientHandler.CookieContainer.GetCookies(wsSigninUrl)["rtFA"].Value;
                spoAuthCookies.Expires = stsToken.Expires;
                spoAuthCookies.Host = wsSigninUrl;
                if (verbose) Console.WriteLine("[OK]");
            }
            catch (Exception e)
            {
               Console.WriteLine("[ERROR]:"+e.Message);
               throw new Exception("Problems retrieving Cookies.");
            }
            return spoAuthCookies;
        }

        private async Task<Uri> GetAdfsAuthUrl()
        {
            // make a post request with the user's login name to MSO HRD (Home Realm Discovery) service 
            // so it can find out the url of the federation service (corporate ADFS) responsible for authenticating the user
            Uri corpAdfsProxyUrl = null;
            if (verbose) Console.Write("Retrieving ADFS URL...");

            try
            { 
                byte[] response = await HttpUtility.SendHttpRequest(
                    new Uri(msoHrdUrl),
                    HttpMethod.Post,
                    new MemoryStream(Encoding.UTF8.GetBytes(String.Format("handler=1&login={0}", this.username))), // pass in the login name in the body of the form
                    "application/x-www-form-urlencoded",
                    null);

                var serializer = new JavaScriptSerializer();
                var deserializedResponse = serializer.Deserialize<Dictionary<string, object>>(Encoding.UTF8.GetString(response, 0, response.Length));
                corpAdfsProxyUrl = deserializedResponse.ContainsKey("AuthURL") ? new Uri(deserializedResponse["AuthURL"] as string) : null;
                if (verbose) {
                    if (corpAdfsProxyUrl != null) Console.WriteLine("[OK]"); else Console.WriteLine("[KO] (Probably not ADFS Federated)");
                }
            }
            catch (Exception e)
            {
                if (verbose) Console.WriteLine("[ERROR]:" + e.Message);
            }
            return corpAdfsProxyUrl;
        }


        private async Task<string> GetAdfsSAMLTokenUsernamePassword()
        {
            // makes a seurity token request to the corporate ADFS proxy usernamemixed endpoint using
            // the user's corporate credentials. The logon token is used to talk to MSO STS to get
            // an O365 service token that can then be used to sign into SPO.
            string samlAssertion = null;

            // the corporate ADFS proxy endpoint that issues SAML seurity tokens given username/password credentials 
            string stsUsernameMixedUrl = String.Format("https://{0}/adfs/services/trust/2005/usernamemixed/", this.adfsAuthUrl.Host);

            // generate the WS-Trust security token request SOAP message passing in the user's corporate credentials 
            // and the site we want access to. We send the token request to the corporate ADFS proxy usernamemixed endpoint.
            byte[] requestBody = Encoding.UTF8.GetBytes(ParameterizeSoapRequestTokenMsgWithUsernamePassword(
                "urn:federation:MicrosoftOnline", // we are requesting a logon token to talk to the Microsoft Federation Gateway
                this.username,
                this.password,
                stsUsernameMixedUrl));
            if (verbose) Console.Write ("Logging in and retrieving SAML Token...");

            try
            {
                byte[] response = await HttpUtility.SendHttpRequest(
                    new Uri(stsUsernameMixedUrl),
                    HttpMethod.Post,
                    new MemoryStream(requestBody),
                    "application/soap+xml; charset=utf-8",
                    null);

                // the logon token is in the SAML assertion element of the message body
                XDocument xDoc = XDocument.Parse(Encoding.UTF8.GetString(response, 0, response.Length), LoadOptions.PreserveWhitespace);
                var assertion = from e in xDoc.Descendants()
                                where e.Name == XName.Get("Assertion", saml)
                                select e;

                samlAssertion = assertion.FirstOrDefault().ToString();

                // for some reason the assertion string needs to be loaded into an XDocument
                // and written out for for the XML to be valid. Otherwise we get an invalid
                // XML error back from ADFSs
                XDocument doc1 = XDocument.Parse(samlAssertion);
                samlAssertion = doc1.ToString(SaveOptions.DisableFormatting);
                if (verbose) Console.WriteLine("[OK]");
            }
            catch (Exception e)
            {
                Console.WriteLine("[ERROR]:" + e.Message);
                throw new Exception("Problems with authentication or SAML token retrieval");
            }

            return samlAssertion; 
        }

        private async Task<string> GetAdfsSAMLTokenWinAuth()
        {
            // makes a security token request to the corporate ADFS proxy integrated auth endpoint.
            // If the user is logged on to a machine joined to the corporate domain with her Windows credentials and connected
            // to the corporate network Kerberos automatically takes care of authenticating the security token 
            // request to ADFS.
            // The logon token is used to talk to MSO STS to get an O365 service token that can then be used to sign into SPO.

            string samlAssertion = null;

            HttpClientHandler handler = new HttpClientHandler();
            handler.UseDefaultCredentials = true; // use the default credentials so Kerberos can take care of authenticating our request
            if (verbose) Console.Write ("Logging in and retrieving SAML Token...");
            try
            {
                byte[] stsresponse = await HttpUtility.SendHttpRequest(
                this.adfsIntegratedAuthUrl,
                HttpMethod.Get,
                null,
                "text/html; charset=utf-8",
                handler);

            StreamReader sr = new StreamReader(new MemoryStream(stsresponse));
            XDocument xDoc = XDocument.Parse(sr.ReadToEnd(), LoadOptions.PreserveWhitespace);

                var body = from e in xDoc.Descendants()
                           where e.Name == XName.Get("body")
                           select e;

                var form = from e in body.FirstOrDefault().Descendants()
                           where e.Name == XName.Get("form")
                           select e;

                // the security token response we got from ADFS is in the wresult input element 
                var wresult = from e in form.FirstOrDefault().Descendants()
                              where e.Name == XName.Get("input") &&
                              e.Attribute(XName.Get("name")) != null &&
                              e.Attribute(XName.Get("name")).Value == "wresult"
                              select e;

                if (wresult.FirstOrDefault() != null)
                {
                    // the logon token is in the SAML assertion element
                    XDocument xDoc1 = XDocument.Parse(wresult.FirstOrDefault().Attribute(XName.Get("value")).Value, LoadOptions.PreserveWhitespace);
                    var assertion = from e in xDoc1.Descendants()
                                    where e.Name == XName.Get("Assertion", saml)
                                    select e;

                    samlAssertion = assertion.FirstOrDefault().ToString();

                    // for some reason the assertion string needs to be loaded into an XDocument
                    // and written out for for the XML to be valid. Otherwise we get an invalid
                    // XML error back from ADFSs
                    XDocument doc1 = XDocument.Parse(samlAssertion);
                    samlAssertion = doc1.ToString(SaveOptions.DisableFormatting);
                }
                if (verbose) Console.WriteLine("[OK]");
            }
            catch (Exception e)
            {
                Console.WriteLine("[ERROR]:" + e.Message);
                throw new Exception("Problems with authentication or SAML token retrieval");
            }

            return samlAssertion;
        }

        
        private async Task<SamlSecurityToken> GetMsoStsSAMLToken()
        {
            // Makes a request that conforms with the WS-Trust standard to 
            // Microsoft Online Services Security Token Service to get a SAML
            // security token back so we can then use it to sign the user to SPO 

            SamlSecurityToken samlST = new SamlSecurityToken();
            byte[] saml11RTBytes = null;
            string logonToken = null;
            try
            { // find out whether the user's domain is a federated domain
                this.adfsAuthUrl = await GetAdfsAuthUrl();

                // get logon token using windows integrated auth when the user is connected to the corporate network 
                if (this.adfsAuthUrl != null && this.useIntegratedWindowsAuth)
                {
                    UriBuilder ub = new UriBuilder();
                    ub.Scheme = this.adfsAuthUrl.Scheme;
                    ub.Host = this.adfsAuthUrl.Host;
                    ub.Path = string.Format("{0}auth/integrated/", this.adfsAuthUrl.LocalPath);

                    // specify in the query string we want a logon token to present to the Microsoft Federation Gateway
                    // for the corresponding user
                    ub.Query = String.Format("{0}&wa=wsignin1.0&wtrealm=urn:federation:MicrosoftOnline", this.adfsAuthUrl.Query.Remove(0, 1)).
                        Replace("&username=", String.Format("&username={0}", this.username));

                    this.adfsIntegratedAuthUrl = ub.Uri;

                    // get the logon token from the corporate ADFS using Windows Integrated Auth
                    logonToken = await GetAdfsSAMLTokenWinAuth();

                    if (!string.IsNullOrEmpty(logonToken))
                    {
                        // generate the WS-Trust security token request SOAP message passing in the logon token we got from the corporate ADFS
                        // and the site we want access to 
                        saml11RTBytes = Encoding.UTF8.GetBytes(ParameterizeSoapRequestTokenMsgWithAssertion(
                            this.spSiteUrl.ToString(),
                            logonToken,
                            msoStsUrl));
                    }
                }

                // get logon token using the user's corporate credentials. Likely when not connected to the corporate network
                if (logonToken == null && this.adfsAuthUrl != null && !string.IsNullOrEmpty(password))
                {
                    logonToken = await GetAdfsSAMLTokenUsernamePassword(); // get the logon token from the corporate ADFS proxy usernamemixed enpoint

                    if (logonToken != null)
                    {
                        // generate the WS-Trust security token request SOAP message passing in the logon token we got from the corporate ADFS
                        // and the site we want access to 
                        saml11RTBytes = Encoding.UTF8.GetBytes(ParameterizeSoapRequestTokenMsgWithAssertion(
                        this.spSiteUrl.ToString(),
                        logonToken,
                        msoStsUrl));
                    }
                }

                if (logonToken == null && this.adfsAuthUrl == null && (!string.IsNullOrEmpty(password))) // login with O365 credentials. Not a federated login.
                {
                    // generate the WS-Trust security token request SOAP message passing in the user's credentials and the site we want access to 
                    saml11RTBytes = Encoding.UTF8.GetBytes(ParameterizeSoapRequestTokenMsgWithUsernamePassword(
                        this.spSiteUrl.ToString(),
                        this.username,
                        this.password,
                        msoStsUrl));
                }

                if (saml11RTBytes != null)
                {
                    // make the post request to MSO STS with the WS-Trust payload
                    byte[] response = await HttpUtility.SendHttpRequest(
                        new Uri(msoStsUrl),
                        HttpMethod.Post,
                        new MemoryStream(saml11RTBytes),
                        "application/soap+xml; charset=utf-8",
                        null);

                    StreamReader sr = new StreamReader(new MemoryStream(response));

                    // the SAML security token is in the BinarySecurityToken element of the message body
                    XDocument xDoc = XDocument.Parse(sr.ReadToEnd());
                    var binaryST = from e in xDoc.Descendants()
                                where e.Name == XName.Get("BinarySecurityToken", wsse)
                                select e;

                    // get the security token expiration date from the message body
                    var expires = from e in xDoc.Descendants()
                                where e.Name == XName.Get("Expires", wsu)
                                select e;

                    if (binaryST.FirstOrDefault() != null && expires.FirstOrDefault() != null)
                    {

                        samlST.Token = Encoding.UTF8.GetBytes(binaryST.FirstOrDefault().Value);
                        samlST.Expires = DateTime.Parse(expires.FirstOrDefault().Value);
                    }
                }
                if (verbose) Console.WriteLine("Retrieving STS Token...[OK]");
            }
            catch (Exception e)
            { 
                Console.WriteLine("Retrieving STS Token...[ERROR]:" + e.Message);
                throw new Exception("Problems retrieving STS Token");
            }
            return samlST;
        }

        private string ParameterizeSoapRequestTokenMsgWithUsernamePassword(string url, string username, string password, string toUrl)
        {
            string samlRTString = "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:a=\"http://www.w3.org/2005/08/addressing\" xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">   <s:Header>     <a:Action s:mustUnderstand=\"1\">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>     <a:ReplyTo>       <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>     </a:ReplyTo>     <a:To s:mustUnderstand=\"1\">[toUrl]</a:To>     <o:Security s:mustUnderstand=\"1\" xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">       <o:UsernameToken>         <o:Username>[username]</o:Username>         <o:Password>[password]</o:Password>       </o:UsernameToken>     </o:Security>   </s:Header>   <s:Body>     <t:RequestSecurityToken xmlns:t=\"http://schemas.xmlsoap.org/ws/2005/02/trust\">       <wsp:AppliesTo xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">         <a:EndpointReference>           <a:Address>[url]</a:Address>         </a:EndpointReference>       </wsp:AppliesTo>       <t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType>       <t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType>       <t:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</t:TokenType>     </t:RequestSecurityToken>   </s:Body> </s:Envelope>";
            samlRTString = samlRTString.Replace("[username]", username);
            samlRTString = samlRTString.Replace("[password]", password);
            samlRTString = samlRTString.Replace("[url]", url);
            samlRTString = samlRTString.Replace("[toUrl]", toUrl);

            return samlRTString;
        }

        private string ParameterizeSoapRequestTokenMsgWithAssertion(string url, string samlAssertion, string toUrl)
        {
            string samlRTString = "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:a=\"http://www.w3.org/2005/08/addressing\" xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">   <s:Header>     <a:Action s:mustUnderstand=\"1\">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>     <a:ReplyTo>       <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>     </a:ReplyTo>     <a:To s:mustUnderstand=\"1\">[toUrl]</a:To>     <o:Security s:mustUnderstand=\"1\" xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">[assertion]     </o:Security>   </s:Header>   <s:Body> <t:RequestSecurityToken xmlns:t=\"http://schemas.xmlsoap.org/ws/2005/02/trust\">       <wsp:AppliesTo xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">         <a:EndpointReference>           <a:Address>[url]</a:Address>         </a:EndpointReference>       </wsp:AppliesTo>       <t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType>       <t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType>       <t:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</t:TokenType>     </t:RequestSecurityToken>   </s:Body> </s:Envelope>";
            samlRTString = samlRTString.Replace("[assertion]", samlAssertion);
            samlRTString = samlRTString.Replace("[url]", url);
            samlRTString = samlRTString.Replace("[toUrl]", toUrl);

            return samlRTString;
        }
    }
}
