using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Google.Authenticator
{
    public class TwoFactorAuthenticator
    {
        private static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        // ReSharper disable once MemberCanBePrivate.Global
        public TimeSpan DefaultClockDriftTolerance { get; }
        // ReSharper disable once MemberCanBePrivate.Global
        public bool UseManagedSha1Algorithm { get; }
        // ReSharper disable once MemberCanBePrivate.Global
        public bool TryUnmanagedAlgorithmOnFailure { get; }

        public TwoFactorAuthenticator() : this(true, true)
        {
        }

        // ReSharper disable once MemberCanBePrivate.Global
        public TwoFactorAuthenticator(bool useManagedSha1, bool useUnmanagedOnFail)
        {
            DefaultClockDriftTolerance = TimeSpan.FromMinutes(5);
            UseManagedSha1Algorithm = useManagedSha1;
            TryUnmanagedAlgorithmOnFailure = useUnmanagedOnFail;
        }

        /// <summary>
        ///     Generate a setup code for a Google Authenticator user to scan.
        /// </summary>
        /// <param name="accountTitleNoSpaces">Account Title (no spaces)</param>
        /// <param name="accountSecretKey">Account Secret Key</param>
        /// <param name="qrCodeWidth">QR Code Width</param>
        /// <param name="qrCodeHeight">QR Code Height</param>
        /// <returns>SetupCode object</returns>
        public SetupCode GenerateSetupCode(string accountTitleNoSpaces, string accountSecretKey, int qrCodeWidth, int qrCodeHeight)
        {
            return GenerateSetupCode(null, accountTitleNoSpaces, accountSecretKey, qrCodeWidth, qrCodeHeight);
        }

        /// <summary>
        ///     Generate a setup code for a Google Authenticator user to scan (with issuer ID).
        /// </summary>
        /// <param name="issuer">Issuer ID (the name of the system, i.e. 'MyApp')</param>
        /// <param name="accountTitleNoSpaces">Account Title (no spaces)</param>
        /// <param name="accountSecretKey">Account Secret Key</param>
        /// <param name="qrCodeWidth">QR Code Width</param>
        /// <param name="qrCodeHeight">QR Code Height</param>
        /// <param name="useHttps">Use HTTPS instead of HTTP</param>
        /// <returns>SetupCode object</returns>
        // ReSharper disable once MemberCanBePrivate.Global
        public SetupCode GenerateSetupCode(string issuer, string accountTitleNoSpaces, string accountSecretKey, int qrCodeWidth, int qrCodeHeight, bool useHttps = false)
        {
            if (accountTitleNoSpaces == null) throw new NullReferenceException("Account Title is null");

            accountTitleNoSpaces = accountTitleNoSpaces.Replace(" ", "");

            var sC = new SetupCode
            {
                Account = accountTitleNoSpaces,
                AccountSecretKey = accountSecretKey
            };

            var encodedSecretKey = EncodeAccountSecretKey(accountSecretKey);
            sC.ManualEntryKey = encodedSecretKey;

            var provisionUrl = 
                UrlEncode(string.IsNullOrEmpty(issuer) ? 
                $"otpauth://totp/{accountTitleNoSpaces}?secret={encodedSecretKey}" :
                $"otpauth://totp/{accountTitleNoSpaces}?secret={encodedSecretKey}&issuer={UrlEncode(issuer)}");

            var protocol = useHttps ? "https" : "http";
            var url = $"{protocol}://chart.googleapis.com/chart?cht=qr&chs={qrCodeWidth}x{qrCodeHeight}&chl={provisionUrl}";

            sC.QrCodeSetupImageUrl = url;

            return sC;
        }

        private string UrlEncode(string value)
        {
            var result = new StringBuilder();
            const string validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";

            foreach (var symbol in value)
                if (validChars.IndexOf(symbol) != -1)
                    result.Append(symbol);
                else
                    result.Append('%' + $"{(int) symbol:X2}");

            return result.ToString().Replace(" ", "%20");
        }

        private string EncodeAccountSecretKey(string accountSecretKey)
        {
            return Base32Encode(Encoding.UTF8.GetBytes(accountSecretKey));
        }

        // ReSharper disable once MemberCanBeMadeStatic.Local
        private string Base32Encode(byte[] data)
        {
            const int inByteSize = 8;
            const int outByteSize = 5;
            var alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".ToCharArray();

            int i = 0, index = 0;
            var result = new StringBuilder((data.Length + 7) * inByteSize / outByteSize);

            while (i < data.Length)
            {
                var currentByte = data[i];

                /* Is the current digit going to span a byte boundary? */
                int digit;
                if (index > inByteSize - outByteSize)
                {
                    var nextByte = i + 1 < data.Length ? data[i + 1] : 0;

                    digit = currentByte & (0xFF >> index);
                    index = (index + outByteSize) % inByteSize;
                    digit <<= index;
                    digit |= nextByte >> (inByteSize - index);
                    i++;
                }
                else
                {
                    digit = (currentByte >> (inByteSize - (index + outByteSize))) & 0x1F;
                    index = (index + outByteSize) % inByteSize;
                    if (index == 0)
                        i++;
                }
                result.Append(alphabet[digit]);
            }

            return result.ToString();
        }

        // ReSharper disable once InconsistentNaming
        public string GeneratePINAtInterval(string accountSecretKey, long counter, int digits = 6)
        {
            return GenerateHashedCode(accountSecretKey, counter, digits);
        }

        private string GenerateHashedCode(string secret, long iterationNumber, int digits = 6)
        {
            var key = Encoding.UTF8.GetBytes(secret);
            return GenerateHashedCode(key, iterationNumber, digits);
        }

        private string GenerateHashedCode(byte[] key, long iterationNumber, int digits = 6)
        {
            var counter = BitConverter.GetBytes(iterationNumber);

            if (BitConverter.IsLittleEndian)
                Array.Reverse(counter);

            var hmac = GetHmacSha1Algorithm(key);

            var hash = hmac.ComputeHash(counter);

            var offset = hash[hash.Length - 1] & 0xf;

            // Convert the 4 bytes into an integer, ignoring the sign.
            var binary =
                ((hash[offset] & 0x7f) << 24)
                | (hash[offset + 1] << 16)
                | (hash[offset + 2] << 8)
                | hash[offset + 3];

            var password = binary % (int) Math.Pow(10, digits);
            return password.ToString(new string('0', digits));
        }

        private long GetCurrentCounter()
        {
            return GetCurrentCounter(DateTime.UtcNow, Epoch, 30);
        }

        private long GetCurrentCounter(DateTime now, DateTime epoch, int timeStep)
        {
            return (long) (now - epoch).TotalSeconds / timeStep;
        }

        /// <summary>
        ///     Creates a HMACSHA1 algorithm to use to hash the counter bytes. By default, this will attempt to use
        ///     the managed SHA1 class (SHA1Manager) and on exception (FIPS-compliant machine policy, etc) will attempt
        ///     to use the unmanaged SHA1 class (SHA1CryptoServiceProvider).
        /// </summary>
        /// <param name="key">User's secret key, in bytes</param>
        /// <returns>HMACSHA1 cryptographic algorithm</returns>
        private HMACSHA1 GetHmacSha1Algorithm(byte[] key)
        {
            HMACSHA1 hmac;

            try
            {
                hmac = new HMACSHA1(key, UseManagedSha1Algorithm);
            }
            catch (InvalidOperationException)
            {
                if (UseManagedSha1Algorithm && TryUnmanagedAlgorithmOnFailure)
                    hmac = new HMACSHA1(key, false);
                else
                    throw;
            }

            return hmac;
        }

        // ReSharper disable once InconsistentNaming
        public bool ValidateTwoFactorPIN(string accountSecretKey, string twoFactorCodeFromClient)
        {
            return ValidateTwoFactorPIN(accountSecretKey, twoFactorCodeFromClient, DefaultClockDriftTolerance);
        }

        // ReSharper disable once InconsistentNaming
        // ReSharper disable once MemberCanBePrivate.Global
        public bool ValidateTwoFactorPIN(string accountSecretKey, string twoFactorCodeFromClient,TimeSpan timeTolerance)
        {
            var codes = GetCurrentPINs(accountSecretKey, timeTolerance);
            return codes.Any(c => c == twoFactorCodeFromClient);
        }

        // ReSharper disable once UnusedMember.Global
        // ReSharper disable once InconsistentNaming
        public string GetCurrentPIN(string accountSecretKey)
        {
            return GeneratePINAtInterval(accountSecretKey, GetCurrentCounter());
        }

        // ReSharper disable once UnusedMember.Global
        // ReSharper disable once InconsistentNaming
        public string GetCurrentPIN(string accountSecretKey, DateTime now)
        {
            return GeneratePINAtInterval(accountSecretKey, GetCurrentCounter(now, Epoch, 30));
        }

        // ReSharper disable once InconsistentNaming
        public string[] GetCurrentPINs(string accountSecretKey)
        {
            return GetCurrentPINs(accountSecretKey, DefaultClockDriftTolerance);
        }

        // ReSharper disable once InconsistentNaming
        // ReSharper disable once MemberCanBePrivate.Global
        public string[] GetCurrentPINs(string accountSecretKey, TimeSpan timeTolerance)
        {
            var codes = new List<string>();
            var iterationCounter = GetCurrentCounter();
            var iterationOffset = 0;

            if (timeTolerance.TotalSeconds > 30)
                iterationOffset = Convert.ToInt32(timeTolerance.TotalSeconds / 30.00);

            var iterationStart = iterationCounter - iterationOffset;
            var iterationEnd = iterationCounter + iterationOffset;

            for (var counter = iterationStart; counter <= iterationEnd; counter++)
                codes.Add(GeneratePINAtInterval(accountSecretKey, counter));

            return codes.ToArray();
        }
    }
}