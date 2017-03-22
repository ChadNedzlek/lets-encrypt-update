namespace CertUpdateLib
{
	public class DomainUpdateConfigurationOutput
	{
		public string PrivateKeyPath { get; set; }

		public string SingleCertificatePath { get; set; }
		public string ChainedCertificatePath { get; set; }
		public string IntermediateCertificatesPath { get; set; }

		public string PfxPath { get; set; }
		public string IntermediatePfxPath { get; set; }
		public DomainUpdateConfigurationStore CertStore { get; set; }
		public DomainUpdateConfigurationIis Iis { get; set; }
	}

	public class DomainUpdateConfigurationIis
	{
		public string Site { get; set; }
		public int Port { get; set; }
	}

	public class DomainUpdateConfigurationStore
	{
		public string Location { get; set; }
		public string Name { get; set; }
	}
}