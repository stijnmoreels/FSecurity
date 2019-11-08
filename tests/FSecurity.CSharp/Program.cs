using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace FSecurity.CSharp
{
    class Program
    {
        public static void Main(string[] args)
        {
            var baseRequest = 
                Request.Endpoint(HttpMethod.Get, "http://something")
                       .WithHeader("x-api-key", "asldfkjasldfkj")
                       .WithRoute("/something");

            Api.PassThru
                     .Should(NotHaveLeakageHeaders)
                     .ScanAsync(baseRequest);

            var scanAsync =
                Api.Inject(Fuzz.Naughty)
                         .Into((value, req) => req.WithHeader("Header", value))
                         .Should(res => res.StatusCode == HttpStatusCode.Accepted
                                     ? (true, Vulnerability.Create(""))
                                     : (false, null))
                         .ScanAsync(Request.Endpoint(HttpMethod.Get, "http://something"));


        }

        private static (bool, Vulnerability) NotHaveLeakageHeaders(HttpResponseMessage response)
        {
            var leakage = Fuzz.HttpLeakageHeaders.Where(response.HasHeader);
            var vulnerability = Vulnerability.Info($"Information leakage of response headers: {String.Join(", ", leakage)}", response);

            return (leakage.Any(), vulnerability);
        }
    }
}
