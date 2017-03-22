namespace CertUpdate
{
	partial class ProjectInstaller
	{
		/// <summary>
		/// Required designer variable.
		/// </summary>
		private System.ComponentModel.IContainer components = null;

		/// <summary> 
		/// Clean up any resources being used.
		/// </summary>
		/// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
		protected override void Dispose(bool disposing)
		{
			if (disposing && (components != null))
			{
				components.Dispose();
			}
			base.Dispose(disposing);
		}

		#region Component Designer generated code

		/// <summary>
		/// Required method for Designer support - do not modify
		/// the contents of this method with the code editor.
		/// </summary>
		private void InitializeComponent()
		{
			this.certificateRenewalProcessInstaller = new System.ServiceProcess.ServiceProcessInstaller();
			this.certificateRenewalInstaller = new System.ServiceProcess.ServiceInstaller();
			// 
			// certificateRenewalProcessInstaller
			// 
			this.certificateRenewalProcessInstaller.Account = System.ServiceProcess.ServiceAccount.LocalService;
			this.certificateRenewalProcessInstaller.Password = null;
			this.certificateRenewalProcessInstaller.Username = null;
			// 
			// certificateRenewalInstaller
			// 
			this.certificateRenewalInstaller.Description = "Automatically renews specified SSL certificates that are nearing expiration and u" +
    "pdates settings accordingly";
			this.certificateRenewalInstaller.DisplayName = "SSL Certificate Auto-Renewal";
			this.certificateRenewalInstaller.ServiceName = "CertificateRenewalService";
			this.certificateRenewalInstaller.StartType = System.ServiceProcess.ServiceStartMode.Automatic;
			// 
			// ProjectInstaller
			// 
			this.Installers.AddRange(new System.Configuration.Install.Installer[] {
            this.certificateRenewalProcessInstaller,
            this.certificateRenewalInstaller});

		}

		#endregion

		private System.ServiceProcess.ServiceProcessInstaller certificateRenewalProcessInstaller;
		private System.ServiceProcess.ServiceInstaller certificateRenewalInstaller;
	}
}