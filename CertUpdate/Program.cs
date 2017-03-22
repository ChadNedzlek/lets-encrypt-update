using System.ServiceProcess;

namespace CertUpdate
{
	internal static class Program
	{
		/// <summary>
		///     The main entry point for the application.
		/// </summary>
		private static void Main()
		{
			var servicesToRun = new ServiceBase[]
			{
				new CertificateRenewalService()
			};
			ServiceBase.Run(servicesToRun);
		}
	}
}