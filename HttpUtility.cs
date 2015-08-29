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
using System.Text;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.IO;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace Cookie365
{
    internal class HttpUtility
    {
        static bool verbose = false;
        /// <summary>
        /// Sends a JSON OData request appending the SharePoint canary to the request header.
        /// Appending the canary to the request is necessary to perform write operations (e.g. create, update, delete list items)
        /// The canary is a security measure to prevent cross site scripting attacks
        /// </summary>
        /// <param name="uri">The request uri</param>
        /// <param name="method">The http method</param>
        /// <param name="requestContent">A stream containing the request content</param>
        /// <param name="clientHandler">The request client handler</param>
        /// <param name="authUtility">An instance of the auth helper to perform authenticated calls to SPO</param>
        /// <returns></returns>
        public static async Task<byte[]> SendODataJsonRequestWithCanary(Uri uri, HttpMethod method, Stream requestContent, HttpClientHandler clientHandler, SpoAuthUtility authUtility, bool _verbose)
        {
            verbose = _verbose;
            // Make a post request to {siteUri}/_api/contextinfo to get the canary
            var response = await HttpUtility.SendODataJsonRequest(
                new Uri(String.Format("{0}/_api/contextinfo", SpoAuthUtility.Current.SiteUrl)),
                HttpMethod.Post,
                null,
                clientHandler,
                SpoAuthUtility.Current);

            var serializer = new JavaScriptSerializer();
            var deserializedResponse = serializer.Deserialize<Dictionary<string, object>>(Encoding.UTF8.GetString(response, 0, response.Length));
            string canary = deserializedResponse["AuthURL"] as string;

            // Make the OData request passing the canary in the request headers
            return await HttpUtility.SendODataJsonRequest(
                uri,
                method,
                requestContent,
                clientHandler,
                SpoAuthUtility.Current, 
                new Dictionary<string, string> { 
                { "X-RequestDigest", canary  } 
                });
        }

        /// <summary>
        /// Sends a JSON OData request appending SPO auth cookies to the request header.
        /// </summary>
        /// <param name="uri">The request uri</param>
        /// <param name="method">The http method</param>
        /// <param name="requestContent">A stream containing the request content</param>
        /// <param name="clientHandler">The request client handler</param>
        /// <param name="authUtility">An instance of the auth helper to perform authenticated calls to SPO</param>
        /// <param name="headers">The http headers to append to the request</param>
        public static async Task<byte[]> SendODataJsonRequest(Uri uri, HttpMethod method, Stream requestContent, HttpClientHandler clientHandler, SpoAuthUtility authUtility, Dictionary<string, string> headers = null)
        {
            if (clientHandler.CookieContainer == null)
                clientHandler.CookieContainer = new CookieContainer();

            CookieContainer cookieContainer = await authUtility.GetCookieContainer(); // get the auth cookies from SPO after authenticating with Microsoft Online Services STS

            foreach (Cookie c in cookieContainer.GetCookies(uri))
            {
                clientHandler.CookieContainer.Add(uri, c); // apppend SPO auth cookies to the request
            }

            return await SendHttpRequest(
                uri, 
                method, 
                requestContent, 
                "application/json;odata=verbose;charset=utf-8", // the http content type for the JSON flavor of SP REST services 
                clientHandler, 
                headers);
        }

        /// <summary>
        /// Sends an http request to the specified uri and returns the response as a byte array 
        /// </summary>
        /// <param name="uri">The request uri</param>
        /// <param name="method">The http method</param>
        /// <param name="requestContent">A stream containing the request content</param>
        /// <param name="contentType">The content type of the http request</param>
        /// <param name="clientHandler">The request client handler</param>
        /// <param name="headers">The http headers to append to the request</param>
        public static async Task<byte[]> SendHttpRequest(Uri uri, HttpMethod method, Stream requestContent = null, string contentType = null, HttpClientHandler clientHandler = null, Dictionary<string, string> headers = null)
        {
            if (clientHandler == null)
            {
                if (WebRequest.DefaultWebProxy.GetProxy(uri).ToString() != uri.ToString())
                {
                    if (verbose) Console.WriteLine("Using proxy...[" + WebRequest.DefaultWebProxy.GetProxy(uri).ToString()+"]");
                    clientHandler = new HttpClientHandler();
                    WebProxy proxy = new WebProxy((WebRequest.DefaultWebProxy.GetProxy(uri)));
                    proxy.Credentials = CredentialCache.DefaultCredentials;
                    proxy.UseDefaultCredentials = true;
                    clientHandler.UseCookies = true;
                    clientHandler.UseProxy = true;
                    clientHandler.Proxy = proxy;
                }
            }
            var req = clientHandler == null ? new HttpClient() : new HttpClient(clientHandler as HttpMessageHandler);
            var message = new HttpRequestMessage(method, uri);
            byte[] response;

            req.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)");
            message.Headers.Add("Accept", contentType); // set the content type of the request
                
            if (requestContent != null && (method == HttpMethod.Post || method == HttpMethod.Put || method == HttpMethod.Delete))
            {
                message.Content = new StreamContent(requestContent); //set the body for the request

                if (!string.IsNullOrEmpty(contentType))
                {
                    message.Content.Headers.Add("Content-Type", contentType); // if the request has a body set the MIME type
                }
            }

            // append additional headers to the request
            if (headers != null)
            {
                foreach (var header in headers)
                {
                    if (message.Headers.Contains(header.Key))
                    {
                        message.Headers.Remove(header.Key);
                    }

                    message.Headers.Add(header.Key, header.Value);
                }
            }

            // Send the request and read the response as an array of bytes
            using (var res = await req.SendAsync(message))
            {
                response = await res.Content.ReadAsByteArrayAsync();
            }

            return response;
        }
       }
}