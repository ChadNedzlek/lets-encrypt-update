namespace CertUpdateLib
{
	public class DomainUpdateConfiguration
	{
		public DomainUpdateConfigurationOutput Output { get; set; }
		public string PrivateKeyName { get; set; }
		public string Name { get; set; }
		public string[] SubDomains { get; set; }
	}
}