using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Jose;
using Microsoft.Web.Administration;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace CertUpdateLib
{
	public class CertificateUpdater
	{
		private static readonly Regex _linkHeaderPattern = new Regex(@"^<(.*)>(?:;rel=""(.*)"")?$");

		private string _currentNonce;

		public CertificateUpdater(string accountKeyPath, string domain, params string[] subDomains)
		{
			AccountKeyPath = accountKeyPath;
			Domain = domain;
			SubDomains = subDomains;
		}

		public string AccountKeyPath { get; }
		public string Domain { get; }
		public string[] SubDomains { get; }

		public event Action<string> OnError;
		public event Action<string> OnStatusUpdate;

		public async Task<bool> GeneratCertificate(DomainUpdateConfigurationOutput output, CancellationToken cancellationToken)
		{
			if (output.PrivateKeyPath == null)
				throw new ArgumentException("PrivateKeyPath required", nameof(output));

			using (var httpClient = new HttpClient())
			{
				using (var rsa = new RSACryptoServiceProvider())
				{
					RSAParameters rsaParameters;
					OnStatusUpdate?.Invoke("Reading key information...");
					RsaPrivateCrtKeyParameters rsaPrivateKey;
					using (FileStream accountKeyStream = File.OpenRead(AccountKeyPath))
					using (var accountKeyReader = new StreamReader(accountKeyStream))
					{
						var keyPair = (AsymmetricCipherKeyPair) new PemReader(accountKeyReader).ReadObject();
						rsaPrivateKey = (RsaPrivateCrtKeyParameters) keyPair.Private;
						rsaParameters = DotNetUtilities.ToRSAParameters(rsaPrivateKey);
						rsa.ImportParameters(rsaParameters);
					}

					OnStatusUpdate?.Invoke("Generating CSR...");
					byte[] csr = GenerateCertificateRequest(output.PrivateKeyPath);

					IDictionary<string, string> urls;
					OnStatusUpdate?.Invoke("Getting directory information...");
					using (
						HttpResponseMessage dirResponse = await httpClient.GetAsync(
							"https://acme-v01.api.letsencrypt.org/directory",
							cancellationToken))
					{
						UpdateNonce(dirResponse);
						if (!dirResponse.IsSuccessStatusCode)
						{
							OnError?.Invoke("directory failed: " + await dirResponse.Content.ReadAsStringAsync());
							return false;
						}

						urls = JsonConvert.DeserializeObject<IDictionary<string, string>>(await dirResponse.Content.ReadAsStringAsync());
					}

					var payload = new Dictionary<string, object>
					{
						{"resource", "new-cert"},
						{"csr", Base64Url.Encode(csr)}
					};

					cancellationToken.ThrowIfCancellationRequested();
					X509Certificate2 cert;
					var intermediateCerts = new List<X509Certificate2>();
					HttpResponseMessage newCertResponse;
					using (newCertResponse = await httpClient.PostAsync(
						urls["new-cert"],
						new StringContent(CreateJwsBody(payload, rsa, rsaParameters)),
						cancellationToken))
					{
						UpdateNonce(newCertResponse);
						if (newCertResponse.StatusCode == HttpStatusCode.Forbidden)
						{
							cancellationToken.ThrowIfCancellationRequested();
							OnStatusUpdate?.Invoke("Forbidden found, attempting new account registration...");
							newCertResponse.Dispose();
							if (!await TryRegisterApplicationAsync(httpClient, urls, rsa, rsaParameters, cancellationToken))
								return false;
							
							newCertResponse = await httpClient.PostAsync(
								urls["new-cert"],
								new StringContent(CreateJwsBody(payload, rsa, rsaParameters)),
								cancellationToken);
							UpdateNonce(newCertResponse);
						}

						if (newCertResponse.StatusCode == HttpStatusCode.Forbidden)
						{
							cancellationToken.ThrowIfCancellationRequested();
							newCertResponse.Dispose();

							OnStatusUpdate?.Invoke($"Forbidden found, attempting authorization for {Domain}...");
							if (!await TryRunAuthorizationsAsync(httpClient, Domain, urls, rsa, rsaParameters, cancellationToken))
								return false;

							foreach (string subDomain in SubDomains)
							{
								cancellationToken.ThrowIfCancellationRequested();
								OnStatusUpdate?.Invoke($"Forbidden found, attempting authorization for {subDomain}.{Domain}...");
								if (
									!await TryRunAuthorizationsAsync(
										httpClient,
										$"{subDomain}.{Domain}",
										urls,
										rsa,
										rsaParameters,
										cancellationToken))
									return false;
							}

							// Try again now that we are authorized
							newCertResponse = await httpClient.PostAsync(
								urls["new-cert"],
								new StringContent(CreateJwsBody(payload, rsa, rsaParameters)),
								cancellationToken);
							UpdateNonce(newCertResponse);
						}

						if (!newCertResponse.IsSuccessStatusCode)
						{
							OnError?.Invoke("new-cert failed: " + await newCertResponse.Content.ReadAsStringAsync());
							return false;
						}

						byte[] certBytes = await newCertResponse.Content.ReadAsByteArrayAsync();
						cert = new X509Certificate2(certBytes);

						OnStatusUpdate?.Invoke("Fetching intermediate certificates...");
						if (!await TryFillIssuersAsync(httpClient, newCertResponse, intermediateCerts, cancellationToken))
							return false;
					}

					SaveCertificates(output, cert, rsaPrivateKey, intermediateCerts);
				}
			}

			return true;
		}

		private void SaveCertificates(DomainUpdateConfigurationOutput outputDirectory, X509Certificate2 cert, RsaPrivateCrtKeyParameters rsaPrivateKey, List<X509Certificate2> intermediateCerts)
		{
			X509Certificate bcCert = DotNetUtilities.FromX509Certificate(cert);
			string alias = $"{Domain} (exp: {cert.NotAfter:d})";
			
			{
				var store = new Pkcs12Store();
				var certEntry = new X509CertificateEntry(bcCert);
				store.SetCertificateEntry(alias, certEntry);
				store.SetKeyEntry(alias, new AsymmetricKeyEntry(rsaPrivateKey), new[] {certEntry});
				using (MemoryStream stream = new MemoryStream())
				{
					store.Save(stream, null, new SecureRandom());
					stream.Seek(0, SeekOrigin.Begin);
					cert = new X509Certificate2(
						stream.ToArray(),
						(string) null,
						X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet);
				}
			}

			if (!String.IsNullOrEmpty(outputDirectory.PfxPath))
			{
				OnStatusUpdate?.Invoke("Exporting PFX...");
			}

			if (!String.IsNullOrEmpty(outputDirectory.SingleCertificatePath))
			{
				OnStatusUpdate?.Invoke("Exporting CRT...");
				byte[] pfxBytes = cert.Export(X509ContentType.Cert);
				using (FileStream pfxStream = File.Create(outputDirectory.SingleCertificatePath))
				using (var pfxWriter = new BinaryWriter(pfxStream))
				{
					pfxWriter.Write(pfxBytes);
				}
			}

			if (!String.IsNullOrEmpty(outputDirectory.ChainedCertificatePath))
			{
				OnStatusUpdate?.Invoke("Exporting Chained CRT...");
				using (StreamWriter fileWriter = File.CreateText(outputDirectory.ChainedCertificatePath))
				{
					var writer = new PemWriter(fileWriter);
					writer.WriteObject(bcCert);
					foreach (X509Certificate2 issuer in intermediateCerts)
						writer.WriteObject(DotNetUtilities.FromX509Certificate(issuer));
				}
			}

			if (!String.IsNullOrEmpty(outputDirectory.IntermediateCertificatesPath))
			{
				OnStatusUpdate?.Invoke("Exporting Intermediate CRT...");
				using (StreamWriter fileWriter = File.CreateText(outputDirectory.IntermediateCertificatesPath))
				{
					var writer = new PemWriter(fileWriter);
					foreach (X509Certificate2 issuer in intermediateCerts)
						writer.WriteObject(DotNetUtilities.FromX509Certificate(issuer));
				}
			}

			if (!String.IsNullOrEmpty(outputDirectory.IntermediatePfxPath))
			{
				OnStatusUpdate?.Invoke("Exporting Intermediate PFX...");
				X509Certificate2Collection coll = new X509Certificate2Collection(intermediateCerts.ToArray());
				byte[] pfxBytes = coll.Export(X509ContentType.Pfx);
				using (FileStream pfxStream = File.Create(outputDirectory.IntermediatePfxPath))
				using (var pfxWriter = new BinaryWriter(pfxStream))
				{
					pfxWriter.Write(pfxBytes);
				}
			}

			if (outputDirectory.CertStore != null)
			{
				OnStatusUpdate?.Invoke("Saving to cert store...");

				var pkcs12Store = new Pkcs12Store();
				var certEntry = new X509CertificateEntry(bcCert);
				pkcs12Store.SetCertificateEntry(alias, certEntry);
				pkcs12Store.SetKeyEntry(alias, new AsymmetricKeyEntry(rsaPrivateKey), new[] { certEntry });

				X509Certificate2 keyedCert;
				
				var storeLocation = (StoreLocation)Enum.Parse(typeof(StoreLocation), outputDirectory.CertStore.Location, true);
				var storeName = (StoreName)Enum.Parse(typeof(StoreName), outputDirectory.CertStore.Name, true);

				using (MemoryStream pfxStream = new MemoryStream())
				{
					pkcs12Store.Save(pfxStream, null, new SecureRandom());
					pfxStream.Seek(0, SeekOrigin.Begin);

					keyedCert = new X509Certificate2(
						pfxStream.ToArray(),
						(string)null,
						X509KeyStorageFlags.PersistKeySet | (storeLocation == StoreLocation.LocalMachine ? X509KeyStorageFlags.MachineKeySet : X509KeyStorageFlags.UserKeySet));
				}

				var store = new X509Store(storeName,storeLocation);
				store.Open(OpenFlags.ReadWrite);
				store.Add(keyedCert);
				store.Close();

				var intermediates = new X509Store(StoreName.CertificateAuthority, storeLocation);
				intermediates.Open(OpenFlags.ReadWrite);
				foreach (var i in intermediateCerts)
				{
					intermediates.Add(i);
				}
				intermediates.Close();

				if (outputDirectory.Iis != null)
				{
					OnStatusUpdate?.Invoke("Updating IIS sites...");
					ServerManager manager = new ServerManager();
					var site = manager.Sites.FirstOrDefault(s => s.Name == outputDirectory.Iis.Site);
					if (site == null)
					{
						OnError?.Invoke($"Unable to find site {outputDirectory.Iis.Site}");
						return;
					}

					foreach (var b in site.Bindings)
					{
						if (b.Protocol == "https")
						{
							if (outputDirectory.Iis.Port == 0 || b.EndPoint.Port == outputDirectory.Iis.Port)
							{
								OnStatusUpdate?.Invoke($"  Updating port {b.EndPoint.Port}...");
								b.CertificateHash = keyedCert.GetCertHash();
								b.CertificateStoreName = store.Name;
							}
						}
					}

					OnStatusUpdate?.Invoke("  Commiting site changes...");
					manager.CommitChanges();

					site.Stop();
					site.Start();
				}
			}
		}

		private async Task<bool> TryRunAuthorizationsAsync(
			HttpClient httpClient,
			string target,
			IDictionary<string, string> urls,
			RSACryptoServiceProvider rsa,
			RSAParameters rsaParameters,
			CancellationToken cancellationToken)
		{
			var payload = new Dictionary<string, object>
			{
				{"resource", "new-authz"},
				{
					"identifier", new Dictionary<string, object>
					{
						{"type", "simpleHttp"},
						{"value", target}
					}
				}
			};

			AuthorizationChallenge httpSimple;
			Uri location;
			using (
				HttpResponseMessage authz = await httpClient.PostAsync(
					urls["new-authz"],
					new StringContent(CreateJwsBody(payload, rsa, rsaParameters)),
					cancellationToken))
			{
				UpdateNonce(authz);
				if (!authz.IsSuccessStatusCode)
				{
					OnError?.Invoke("new-authz failed: " + await authz.Content.ReadAsStringAsync());
					return false;
				}

				var values = JsonConvert.DeserializeObject<AuthorizationResponse>(await authz.Content.ReadAsStringAsync());

				httpSimple = values.Challenges.FirstOrDefault(c => c.Type == "http-01");

				if (httpSimple == null)
				{
					OnError?.Invoke("new-authz, no simpleHttp option provided");
					return false;
				}
			}

			var challengePayload = new Dictionary<string, object>
			{
				{"resource", "challenge"},
				{"type", httpSimple.Type},
				{"keyAuthorization", $"{httpSimple.Token}.{GetAccountKeyThumbprint(rsaParameters)}"}
			};

			OnStatusUpdate?.Invoke($"Intiating challenge for {target} ...");
			using (
				HttpResponseMessage simpleChallenge = await httpClient.PostAsync(
					httpSimple.Uri,
					new StringContent(CreateJwsBody(challengePayload, rsa, rsaParameters), Encoding.UTF8),
					cancellationToken))
			{
				UpdateNonce(simpleChallenge);
				if (!simpleChallenge.IsSuccessStatusCode)
				{
					OnError?.Invoke("httpSimple failed: " + await simpleChallenge.Content.ReadAsStringAsync());
					return false;
				}
				location = simpleChallenge.Headers.Location;
			}

			string status;
			do
			{
				using (HttpResponseMessage statusCheck = await httpClient.GetAsync(location, cancellationToken))
				{
					UpdateNonce(statusCheck);
					if (!statusCheck.IsSuccessStatusCode)
					{
						OnError?.Invoke("httpSimple failed: " + await statusCheck.Content.ReadAsStringAsync());
						return false;
					}
					var challengeResponse =
						JsonConvert.DeserializeObject<IDictionary<string, object>>(await statusCheck.Content.ReadAsStringAsync());
					status = (string) challengeResponse["status"];

					OnStatusUpdate?.Invoke($"Challenge status: {status}...");
				}
			} while (status == "pending");
			return true;
		}

		private async Task<bool> TryRegisterApplicationAsync(
			HttpClient httpClient,
			IDictionary<string, string> urls,
			RSACryptoServiceProvider rsa,
			RSAParameters rsaParameters,
			CancellationToken cancellationToken)
		{
			var payload = new Dictionary<string, object>
			{
				{"resource", "new-reg"}
			};

			Uri location = null;
			{
				HttpResponseMessage registration;
				using (
					registration =
						await httpClient.PostAsync(
							urls["new-reg"],
							new StringContent(CreateJwsBody(payload, rsa, rsaParameters)),
							cancellationToken))
				{
					UpdateNonce(registration);
					if (registration.StatusCode == HttpStatusCode.Conflict)
					{
						location = registration.Headers.Location;
						registration.Dispose();

						payload["resource"] = "reg";
						registration = await httpClient.PostAsync(
							location,
							new StringContent(CreateJwsBody(payload, rsa, rsaParameters)),
							cancellationToken);
						UpdateNonce(registration);
					}

					if (!registration.IsSuccessStatusCode)
					{
						OnError?.Invoke("new-reg failed: " + await registration.Content.ReadAsStringAsync());
						return false;
					}

					location = location ?? registration.Headers.Location;

					payload["resource"] = "reg";
					IDictionary<string, IEnumerable<string>> links = ParseLinks(registration.Headers.GetValues("Link"));
					payload["agreement"] = links["terms-of-service"].FirstOrDefault();
					_currentNonce = registration.Headers.GetValues("Replay-Nonce").FirstOrDefault();
				}
			}

			using (
				HttpResponseMessage signTos = await httpClient.PostAsync(
					location,
					new StringContent(CreateJwsBody(payload, rsa, rsaParameters)),
					cancellationToken))
			{
				UpdateNonce(signTos);
				if (!signTos.IsSuccessStatusCode)
				{
					OnError?.Invoke("agreeing to terms-of-service failed: " + await signTos.Content.ReadAsStringAsync());
					return false;
				}
			}

			return true;
		}

		private void UpdateNonce(HttpResponseMessage lastRequest)
		{
			IEnumerable<string> nonce;
			if (lastRequest.Headers.TryGetValues("Replay-Nonce", out nonce))
				_currentNonce = nonce.FirstOrDefault();
		}

		private async Task<bool> TryFillIssuersAsync(
			HttpClient httpClient,
			HttpResponseMessage response,
			List<X509Certificate2> certs,
			CancellationToken cancellationToken)
		{
			IEnumerable<string> linkHeaders;
			if (!response.Headers.TryGetValues("Link", out linkHeaders))
				return true;
			response.Dispose();
			IDictionary<string, IEnumerable<string>> headers = ParseLinks(linkHeaders);
			IEnumerable<string> issuerHref;
			if (!headers.TryGetValue("up", out issuerHref))
				return true;

			string href = issuerHref.FirstOrDefault();
			using (HttpResponseMessage issuerRequest = await httpClient.GetAsync(href, cancellationToken))
			{
				UpdateNonce(issuerRequest);
				if (!issuerRequest.IsSuccessStatusCode)
				{
					OnError?.Invoke("get-issuer-cert failed: " + await issuerRequest.Content.ReadAsStringAsync());
					return false;
				}

				byte[] certBytes = await issuerRequest.Content.ReadAsByteArrayAsync();
				certs.Add(new X509Certificate2(certBytes));

				return await TryFillIssuersAsync(httpClient, issuerRequest, certs, cancellationToken);
			}
		}

		private IDictionary<string, IEnumerable<string>> ParseLinks(IEnumerable<string> linkHeaders)
		{
			var links = new Dictionary<string, List<string>>();
			foreach (string header in linkHeaders)
			{
				Match match = _linkHeaderPattern.Match(header);
				if (!match.Success)
					throw new ArgumentException("Invalid Link value: " + header, nameof(linkHeaders));

				string rel = match.Groups[2].Value;
				string href = match.Groups[1].Value;

				List<string> linkSet;
				if (!links.TryGetValue(rel, out linkSet))
					links.Add(rel, linkSet = new List<string>());

				linkSet.Add(href);
			}
			return links.ToDictionary(x => x.Key, x => (IEnumerable<string>) x.Value);
		}

		private string CreateJwsBody(
			Dictionary<string, object> payload,
			RSACryptoServiceProvider rsa,
			RSAParameters rsaParameters)
		{
			string jwt = JWT.Encode(
				payload,
				rsa,
				JwsAlgorithm.RS256,
				new Dictionary<string, object>
				{
					{"nonce", _currentNonce}
				});

			string[] nonCompact = jwt.Split('.');

			var request = new JObject
			{
				{
					"header", new JObject
					{
						{"alg", "RS256"},
						{
							"jwk", new JObject
							{
								{"kty", "RSA"},
								{"e", Base64Url.Encode(rsaParameters.Exponent)},
								{"n", Base64Url.Encode(rsaParameters.Modulus)}
							}
						}
					}
				},
				{"payload", nonCompact[1]},
				{"protected", nonCompact[0]},
				{"signature", nonCompact[2]}
			};
			return request.ToString();
		}

		private byte[] GenerateCertificateRequest(string privateKeyPath)
		{
			var generator = new RsaKeyPairGenerator();
			generator.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(65537), new SecureRandom(), 2048, 1));
			AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();

			var sanNames =
				new GeneralNames(
					new[] {"", "www.", "mail.", "smtp.", "cloud."}.Select(
							prefix => new GeneralName(GeneralName.DnsName, prefix + "vaettir.net"))
						.ToArray());

			var attributes = new DerSet(
				new DerSequence(
					PkcsObjectIdentifiers.Pkcs9AtExtensionRequest,
					new DerSet(
						new DerSequence(
							new DerSequence(
								X509Extensions.SubjectAlternativeName,
								new DerOctetString(sanNames)
							)
						)
					)
				)
			);

			var req = new Pkcs10CertificationRequest(
				new Asn1SignatureFactory(PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id, keyPair.Private),
				new X509Name(
					new[] {X509Name.CN, X509Name.C},
					new Dictionary<DerObjectIdentifier, string>
					{
						{X509Name.CN, Domain},
						{X509Name.C, "US"}
					}),
				keyPair.Public,
				attributes,
				keyPair.Private);

			WritePem(privateKeyPath, keyPair.Private);

			return req.GetDerEncoded();
		}

		private static void WritePem(string outputPath, object obj)
		{
			using (StreamWriter fileWriter = File.CreateText(outputPath))
			{
				var writer = new PemWriter(fileWriter);
				writer.WriteObject(obj);
			}
		}

		private static string GetAccountKeyThumbprint(RSAParameters rsaParameters)
		{
			var obj = new JObject
			{
				{"e", Base64Url.Encode(rsaParameters.Exponent)},
				{"kty", "RSA"},
				{"n", Base64Url.Encode(rsaParameters.Modulus)}
			};

			string keyPart = obj.ToString(Formatting.None);
			using (SHA256 sha = SHA256.Create())
			{
				return Base64Url.Encode(sha.ComputeHash(Encoding.UTF8.GetBytes(keyPart)));
			}
		}

		private class AuthorizationResponse
		{
			public string Status { get; set; }
			public AuthorizationIdentifier Identifier { get; set; }
			public AuthorizationChallenge[] Challenges { get; set; }
			public int[][] Combinations { get; set; }
		}

		private class AuthorizationIdentifier
		{
			public string Type { get; set; }
			public string Value { get; set; }
		}

		private class AuthorizationChallenge
		{
			public string Type { get; set; }
			public string Uri { get; set; }
			public string Token { get; set; }
		}
	}
}