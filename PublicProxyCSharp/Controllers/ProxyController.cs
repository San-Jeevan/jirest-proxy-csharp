using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http;


namespace PublicProxyCSharp.Controllers
{
    [RoutePrefix("api/proxy")]
    public class ProxyController: ApiController
    {
        public class CorsProxyRequest
        {
            public string method { get; set; }
            public string url { get; set; }
            public string protocol { get; set; }
            public List<string> headers { get; set; }
            public string body { get; set; }

        }

        public class CorsProxyResponse : AbstractResponse
        {
            public string method { get; set; }
            public string url { get; set; }
            public string reqheaders { get; set; }
            public string respheaders { get; set; }
            public string reqbody { get; set; }
            public string respbody { get; set; }

            public string bodySize { get; set; }
            public string protocol { get; set; }
        }

        public class AbstractResponse
        {
            public bool success { get; set; }
            public string message { get; set; }
            public List<string> details { get; set; }

        }

        public class AbstractRequest
        {
            public string jwt { get; set; }
            public string ClientKey { get; set; }
        }

        private static Encoding StringToEncoding(string charset)
        {
            if (charset.Contains("utf-8")) return Encoding.UTF8;
            if (charset.Contains("utf-32")) return Encoding.UTF32;
            if (charset.Contains("utf-7")) return Encoding.UTF7;
            if (charset.Contains("us-ascii")) return Encoding.ASCII;
            return Encoding.UTF8;
        }

        public async Task<CorsProxyResponse> ProxyOther(CorsProxyRequest req)
        {
            try
            {
                //IGNORE SSL ERRORS AND FORCE USAGE OF KNOWN ALGORITHM.
                ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls
                            | SecurityProtocolType.Tls11
                            | SecurityProtocolType.Tls12
                            | SecurityProtocolType.Ssl3;

               
                var requesturl = new Uri(req.url);
                HttpClientHandler httpClientHandler = new HttpClientHandler() { AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate };
                httpClientHandler.CookieContainer = new CookieContainer();

                HttpClient httpClient = new HttpClient(httpClientHandler);
                httpClient.MaxResponseContentBufferSize = 256000;
                var propfindMethod = new HttpMethod(req.method);

                var propfindHttpRequestMessage = new HttpRequestMessage(propfindMethod, req.url);


                var ctEncoding = Encoding.UTF8;
                if (req.method.ToLower() != "get") propfindHttpRequestMessage.Content = new StringContent(req.body);
                //HEADER
                

                if (req.headers != null)
                {
                    for (int i = 0; i < req.headers.Count; i++)
                    {
                        var header = req.headers[i];
                        if (!header.Contains(":")) continue;
                        var headerkey = header.Split(':')[0];
                        var headervalue = header.Split(':')[1];


                        //Content-Type
                            if (headerkey.ToLower() == "content-type")
                        {
                            if (req.method.ToLower() == "get")
                            {
                                continue;
                            }
                            if (headervalue.ToLower().Contains("charset"))
                            {
                                ctEncoding = StringToEncoding(headervalue.ToLower());
                            }

                            if (headervalue.Contains(";")) headervalue = headervalue.Split(';')[0];
                            propfindHttpRequestMessage.Content = new StringContent(req.body, ctEncoding,
                                headervalue.Replace(" ", String.Empty));
                            continue; //adding this to request headers causes Misused header error
                        }

                        //COOKIES
                        if (headerkey.ToLower() == "cookie")
                        {
                            var cookies = headervalue.Replace(" ", String.Empty).Split(';');
                            foreach (var cookie in cookies)
                            {
                                var name = cookie.Split('=')[0];
                                var value = cookie.Split('=')[1];
                                httpClientHandler.CookieContainer.Add(requesturl, new Cookie(name, value));
                            }
                            continue; //adding this to request headers causes Misused header error
                        }

                        propfindHttpRequestMessage.Headers.Add(headerkey, headervalue);
                    }
                }
                

                var propfindHttpResponseMesage = await httpClient.SendAsync(propfindHttpRequestMessage);
                var respheaders = propfindHttpResponseMesage.Headers.ToString();
                var ctheaders = propfindHttpResponseMesage.Content.Headers;
                var ggg = string.Join("\r\n", ctheaders.Select(h => h.Key + ": " + string.Join(", ", h.Value)));
                respheaders = respheaders + string.Join("\r\n", ggg) + "\r\n";
                string respbody = await propfindHttpResponseMesage.Content.ReadAsStringAsync();
                var ctlength = propfindHttpResponseMesage.Content.Headers.ContentLength != null ? propfindHttpResponseMesage.Content.Headers.ContentLength.ToString() : "0";
                respheaders = respheaders + string.Join("\r\n", "Content-Length: "+ ctlength);

                return new CorsProxyResponse()
                {
                    success = true,
                    details = new List<string>(),
                    message = "",
                    url = req.url,
                    method = req.method,
                    reqbody = req.body,
                    reqheaders = req.headers == null ? "": string.Join("\r\n", req.headers),
                    respbody = respbody,
                    respheaders = respheaders,
                    bodySize = int.Parse(ctlength).ToString("# ##0"),
                    protocol = "HTTP/1.1"
                };

            }
            catch (Exception e)
            {
                var hostmismatch = false;
                var hostheader = req.headers.FirstOrDefault(x => x.ToLowerInvariant().Contains("host:"));
                if (hostheader != null)
                {
                    var headervalue = hostheader.Split(':')[1];
                    if (!req.url.ToLowerInvariant().Contains(headervalue.Replace(" ",String.Empty)))
                    {
                        hostmismatch = true;
                    }
                }

                if (e.InnerException != null)
                    return new CorsProxyResponse()
                    {
                        details = new List<string>() {e.InnerException.Message},
                        message = e.InnerException.Message + (hostmismatch ? " " + "It appears your host header is not the same as request url. This may be the cause? Try removing it completely or set it to be correct." : ""),
                        success = false,
                        url = req.url,
                        method = req.method,
                        reqbody = req.body,
                        reqheaders = req.headers == null ? "" : string.Join("\r\n", req.headers),
                        protocol = "HTTP/1.1",
                        bodySize = "0"
                    };
                else
                {
                    return new CorsProxyResponse()
                    {
                        details = new List<string>() { e.Message },
                        message = e.Message + (hostmismatch ? " " + "It appears your host header is not the same as request url. This may be the cause? Try removing it completely or set it to be correct." : ""),
                        success = false,
                        url = req.url,
                        method = req.method,
                        reqbody = req.body,
                        reqheaders = req.headers == null ? "" : string.Join("\r\n", req.headers),
                        protocol = "HTTP/1.1",
                        bodySize = "0"
                    };
                }
            }
        }


        [Route("corsBypass")]
        [HttpPost]
        public async Task<CorsProxyResponse> PostCorsBypass(CorsProxyRequest req)
        {
            return await ProxyOther(req);
        }
    }
}