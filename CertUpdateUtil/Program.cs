using System;
using System.IO;
using System.Threading;
using CertUpdateLib;
using Newtonsoft.Json;

namespace CertUpdateUtil
{
	class Program
	{
		static void Main(string[] args)
		{
			CertificateManager mgr = new CertificateManager(@"D:\temp");
			mgr.OnError += err => Console.Error.WriteLine(err);
			mgr.OnStatusUpdate += Console.WriteLine;

			var config = JsonConvert.DeserializeObject<DomainUpdateConfiguration>(File.ReadAllText(@"D:\temp\config\vaettir.net.json"));

			DomainUpdateConfiguration[] configs = {config};

			mgr.UpdateCertificatesAsync(configs, 30, CancellationToken.None).GetAwaiter().GetResult();
		}
	}
}
