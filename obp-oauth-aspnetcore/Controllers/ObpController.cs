using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using OAuth;
using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace obp_oauth_aspnetcore.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class ObpController : ControllerBase
    {
        private const string RequestUrl = "http://127.0.0.1:8081/oauth/initiate";
        private const string RequestAccessTokenUrl = "http://127.0.0.1:8081/oauth/authorize?oauth_token=";
        private const string RequestAuthTokenUrl = "http://127.0.0.1:8081/oauth/token";
        private static readonly string[] UriRfc3986CharsToEscape = new[] { "!", "*", "'", "(", ")" };
        private const string ConsumerKey = "1ak4zd4t0gijxpsb0xknfgr5bxgodmguylgb0zyp";
        private const string ConsumerSecret = "n15xikx0iuczbl3esmvyvj1txn2y2o2wwpc4fh1i";
        private const string UrlCallback = "http://localhost:5000/api/obp/callback";

        private static string TokenSecret { get; set; }

        [HttpGet]
        public IActionResult Login()
        {
            const string tokenSecret = "";
            const string tokenValue = "";

            string Escape(string s)
            {
                var charsToEscape = new[] { "!", "*", "'", "(", ")" };
                var escaped = new StringBuilder(Uri.EscapeDataString(s));
                foreach (var t in charsToEscape)
                {
                    escaped.Replace(t, Uri.HexEscape(t[0]));
                }
                return escaped.ToString();
            }

            var httpWebRequest = (HttpWebRequest)WebRequest.Create(RequestUrl);
            httpWebRequest.Method = "POST";

            var timeStamp = ((int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds).ToString();
            var nonce = Convert.ToBase64String(Encoding.UTF8.GetBytes(timeStamp));

            var signatureBaseString = Escape(httpWebRequest.Method.ToUpper()) + "&";
            signatureBaseString += EscapeUriDataStringRfc3986(RequestUrl.ToLower()) + "&";
            signatureBaseString += EscapeUriDataStringRfc3986(
                "oauth_callback=" + EscapeUriDataStringRfc3986(UrlCallback) + "&" +
                "oauth_consumer_key=" + EscapeUriDataStringRfc3986(ConsumerKey) + "&" +
                "oauth_nonce=" + EscapeUriDataStringRfc3986(nonce) + "&" +
                "oauth_signature_method=" + EscapeUriDataStringRfc3986("HMAC-SHA1") + "&" +
                "oauth_timestamp=" + EscapeUriDataStringRfc3986(timeStamp) + "&" +
                "oauth_version=" + EscapeUriDataStringRfc3986("1.0"));
            Console.WriteLine(@"signatureBaseString: " + signatureBaseString);

            var key = EscapeUriDataStringRfc3986(ConsumerSecret) + "&" + EscapeUriDataStringRfc3986(tokenSecret);
            var signatureEncoding = new ASCIIEncoding();
            var keyBytes = signatureEncoding.GetBytes(key);
            var signatureBaseBytes = signatureEncoding.GetBytes(signatureBaseString);
            string signatureString;
            using (var hmacsha1 = new HMACSHA1(keyBytes))
            {
                var hashBytes = hmacsha1.ComputeHash(signatureBaseBytes);
                signatureString = Convert.ToBase64String(hashBytes);
            }
            SignatureString = EscapeUriDataStringRfc3986(signatureString);

            string SimpleQuote(string s) => '"' + s + '"';
            var header =
                "OAuth realm=" + SimpleQuote("") + "," +
                "oauth_consumer_key=" + SimpleQuote(ConsumerKey) + "," +
                "oauth_nonce=" + SimpleQuote(nonce) + "," +
                "oauth_signature_method=" + SimpleQuote("HMAC-SHA1") + "," +
                "oauth_timestamp=" + SimpleQuote(timeStamp) + "," +
                "oauth_token=" + SimpleQuote(tokenValue) + "," +
                "oauth_version=" + SimpleQuote("1.0") + "," +
                "oauth_callback=" + SimpleQuote(EscapeUriDataStringRfc3986(UrlCallback)) + "," +
                "oauth_signature=" + SimpleQuote(SignatureString);

            httpWebRequest.Headers.Add(HttpRequestHeader.Authorization, header);

            var response = httpWebRequest.GetResponse();
            var characterSet = ((HttpWebResponse)response).CharacterSet;
            var responseEncoding = characterSet == ""
                ? Encoding.UTF8
                : Encoding.GetEncoding(characterSet ?? "utf-8");
            var responsestream = response.GetResponseStream();
            if (responsestream == null)
            {
                throw new ArgumentNullException(nameof(characterSet));
            }
            using (responsestream)
            {
                var reader = new StreamReader(responsestream, responseEncoding);
                var result = reader.ReadToEnd();

                var splitted = result.Split('&');
                OAuthToken = splitted.GetValue(0).ToString().Split('=')[1];
                OAuthTokenSecret = splitted.GetValue(1).ToString().Split('=')[1];
                var oauth_callback_confirmed_value = Convert.ToBoolean(splitted.GetValue(2).ToString().Split('=')[1]);

                if (!oauth_callback_confirmed_value) return BadRequest();

                var loginUrl = $"{RequestAccessTokenUrl}{OAuthToken}";

                return Ok(new
                {
                    Url = loginUrl
                });
            }

            //oauth_token=PJBGKS2I0F3CYCZ3WAUPULEDZ30OWKLNYJXGFNQX&oauth_token_secret=KMJLASQBXCBQXHMGYFKL5HKMZZE2D0ZDGRW1SOFK&oauth_callback_confirmed=true
        }

        private string EscapeUriDataStringRfc3986(string value)
        {
            // Start with RFC 2396 escaping by calling the .NET method to do the work.
            // This MAY sometimes exhibit RFC 3986 behavior (according to the documentation).
            // If it does, the escaping we do that follows it will be a no-op since the
            // characters we search for to replace can't possibly exist in the string.
            StringBuilder escaped = new StringBuilder(Uri.EscapeDataString(value));

            // Upgrade the escaping to RFC 3986, if necessary.
            for (int i = 0; i < UriRfc3986CharsToEscape.Length; i++)
            {
                escaped.Replace(UriRfc3986CharsToEscape[i], Uri.HexEscape(UriRfc3986CharsToEscape[i][0]));
            }

            // Return the fully-RFC3986-escaped string.
            return escaped.ToString();
        }

        private static string OAuthToken { get; set; }
        private static string OAuthTokenSecret { get; set; }
        private static string SignatureString { get; set; }

        [HttpGet]
        public IActionResult Callback()
        {
            // Read token and verifier
            string token = Request.Query["oauth_token"];
            string verifier = Request.Query["oauth_verifier"];

            string Escape(string s)
            {
                var charsToEscape = new[] { "!", "*", "'", "(", ")" };
                var escaped = new StringBuilder(Uri.EscapeDataString(s));
                foreach (var t in charsToEscape)
                {
                    escaped.Replace(t, Uri.HexEscape(t[0]));
                }
                return escaped.ToString();
            }

            var httpWebRequest = (HttpWebRequest)WebRequest.Create(RequestAuthTokenUrl);
            httpWebRequest.Method = "POST";

            var timeStamp = ((int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds).ToString();
            var nonce = Convert.ToBase64String(Encoding.UTF8.GetBytes(timeStamp));

            var signatureBaseString = Escape(httpWebRequest.Method.ToUpper()) + "&";
            signatureBaseString += EscapeUriDataStringRfc3986(RequestAuthTokenUrl.ToLower()) + "&";
            signatureBaseString += EscapeUriDataStringRfc3986(
                "oauth_consumer_key=" + EscapeUriDataStringRfc3986(ConsumerKey) + "&" +
                "oauth_nonce=" + EscapeUriDataStringRfc3986(nonce) + "&" +
                "oauth_signature_method=" + EscapeUriDataStringRfc3986("HMAC-SHA1") + "&" +
                "oauth_timestamp=" + EscapeUriDataStringRfc3986(timeStamp) + "&" +
                "oauth_token=" + EscapeUriDataStringRfc3986(token) + "&" +
                "oauth_verifier=" + EscapeUriDataStringRfc3986(verifier) + "&" +
                "oauth_version=" + EscapeUriDataStringRfc3986("1.0"));
            Console.WriteLine(@"signatureBaseString: " + signatureBaseString);

            var key = EscapeUriDataStringRfc3986(ConsumerSecret) + "&" + EscapeUriDataStringRfc3986(OAuthTokenSecret);
            var signatureEncoding = new ASCIIEncoding();
            var keyBytes = signatureEncoding.GetBytes(key);
            var signatureBaseBytes = signatureEncoding.GetBytes(signatureBaseString);
            string signatureString;
            using (var hmacsha1 = new HMACSHA1(keyBytes))
            {
                var hashBytes = hmacsha1.ComputeHash(signatureBaseBytes);
                signatureString = Convert.ToBase64String(hashBytes);
            }
            signatureString = EscapeUriDataStringRfc3986(signatureString);

            string SimpleQuote(string s) => '"' + s + '"';
            var header =
                "OAuth " +
                "oauth_verifier=" + SimpleQuote(verifier) + "," +
                "oauth_token=" + SimpleQuote(OAuthToken) + "," +
                "oauth_consumer_key=" + SimpleQuote(ConsumerKey) + "," +
                "oauth_nonce=" + SimpleQuote(nonce) + "," +
                "oauth_signature=" + SimpleQuote(signatureString) + "," +
                "oauth_signature_method=" + SimpleQuote("HMAC-SHA1") + "," +
                "oauth_timestamp=" + SimpleQuote(timeStamp) + "," +
                "oauth_version=" + SimpleQuote("1.0");

            httpWebRequest.Headers.Add(HttpRequestHeader.Authorization, header);

            var response = httpWebRequest.GetResponse();
            var characterSet = ((HttpWebResponse)response).CharacterSet;
            var responseEncoding = characterSet == ""
                ? Encoding.UTF8
                : Encoding.GetEncoding(characterSet ?? "utf-8");
            var responsestream = response.GetResponseStream();
            if (responsestream == null)
            {
                throw new ArgumentNullException(nameof(characterSet));
            }
            using (responsestream)
            {
                var reader = new StreamReader(responsestream, responseEncoding);
                var result = reader.ReadToEnd();

                return Ok(result);
            }
        }

        //[HttpGet]
        //public async Task<IActionResult> OpenOrders()
        //{
        //    const string requestUrl = "https://openapi.etsy.com/v2/shops/YOURSHOPNAME/receipts/open?";

        //    var client = new OAuthRequest
        //    {
        //        Method = "GET",
        //        Type = OAuthRequestType.ProtectedResource,
        //        SignatureMethod = OAuthSignatureMethod.HmacSha1,
        //        ConsumerKey = ConsumerKey,
        //        ConsumerSecret = ConsumerSecret,
        //        Token = OAuthToken,
        //        TokenSecret = OAuthTokenSecret,
        //        RequestUrl = requestUrl,
        //    };

        //    var RequestUrl = requestUrl + client.GetAuthorizationQuery();
        //    var result = await RequestUrl.GetStringAsync();
        //    return Content(result, "application/json");
        //}
    }
}