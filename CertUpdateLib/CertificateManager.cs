using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace CertUpdateLib
{
	public class CertificateManager
	{
		private readonly string _privateKeyPath;

		public event Action<string> OnError;
		public event Action<string> OnStatusUpdate;

		public CertificateManager(string privateKeyPath)
		{
			_privateKeyPath = privateKeyPath;
		}

		public async Task<int> UpdateCertificatesAsync(
			IEnumerable<DomainUpdateConfiguration> configs,
			int expriationBuffer,
			CancellationToken cancellationToken)
		{
			int updated = 0;
			foreach (var domain in configs)
			{
				cancellationToken.ThrowIfCancellationRequested();

				try
				{
					bool certExists = File.Exists(domain.Output.SingleCertificatePath);
					bool upToDate = false;
					if (certExists)
					{
						var x509Certificate2 = new X509Certificate2(domain.Output.SingleCertificatePath);
						TimeSpan remaining = x509Certificate2.NotAfter - DateTime.UtcNow;
						upToDate = remaining.TotalDays > expriationBuffer;
					}

					if (upToDate)
					{
						continue;
					}

					var manager = new CertificateUpdater(
						Path.Combine(_privateKeyPath, domain.PrivateKeyName),
						domain.Name,
						domain.SubDomains);

					var onError = OnError;
					if (onError != null)
						manager.OnError += onError;

					var onStatus = OnStatusUpdate;
					if (onStatus != null)
						manager.OnStatusUpdate += onStatus;

					await manager.GeneratCertificate(domain.Output, cancellationToken);

					updated++;
				}
				catch (Exception e)
				{
					OnError?.Invoke($"Failed to update domain {domain}: {e}");
				}
			}

			return updated;
		}
	}
}