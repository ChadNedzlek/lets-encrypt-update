using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CertUpdate.Properties;
using CertUpdateLib;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.OpenSsl;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace CertUpdate
{
	public partial class CertificateRenewalService : ServiceBase
	{
		private Task _executingTask;
		private CancellationTokenSource _cancellation;

		public CertificateRenewalService()
		{
			InitializeComponent();
		}

		protected override void OnStart(string[] args)
		{
			_cancellation = new CancellationTokenSource();
			_executingTask = Task.Run(() => TrackRenewals(_cancellation.Token), _cancellation.Token);
		}

		protected override void OnStop()
		{
			_cancellation.Cancel();
			try
			{
				_executingTask?.Wait();
			}
			catch (OperationCanceledException)
			{
			}
		}

		private async Task TrackRenewals(CancellationToken cancellationToken)
		{
			while (!cancellationToken.IsCancellationRequested)
			{
				CertificateManager mgr = new CertificateManager(Settings.Default.PrivateKeyPath);
				mgr.OnError += err => Trace.TraceError(err);
				mgr.OnStatusUpdate += msg => Trace.TraceInformation(msg);

				var configurations = Directory.GetFiles(Settings.Default.DomainConfigPath, "*.*", SearchOption.AllDirectories)
					.Select(LoadConfiguration);

				await mgr.UpdateCertificatesAsync(configurations, Settings.Default.RenewBufferDays, cancellationToken);

				Trace.TraceInformation("Resting 6 hours");
				await Task.Delay(TimeSpan.FromHours(6), cancellationToken);
			}
		}

		private DomainUpdateConfiguration LoadConfiguration(string path)
		{
			using (var textReader = File.OpenText(path))
			using (var jsonReader = new JsonTextReader(textReader))
			{
				return new JsonSerializer().Deserialize<DomainUpdateConfiguration>(jsonReader);
			}
		}
	}
}
