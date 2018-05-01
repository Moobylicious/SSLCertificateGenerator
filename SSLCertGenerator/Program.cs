using NDesk.Options;
using NDesk.Options.Extensions;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace SSLCertGenerator
{
    class Program
    {
        static void Main(string[] args)
        {
            var opts = new OptionSet();
            var friendlyName = opts.AddVariable<string>("friendlyname", "(required) friendly name of cert to generate");
            var operatorName = opts.AddVariable<string>("operator", "operator name");
            var siteId = opts.AddVariable<string>("siteid", "Site Id");
            var seq = opts.AddVariable<int>("seq", "Sequence no");
            var server = opts.AddSwitch("server", "create server certificate");
            var delete = opts.AddSwitch("delete", "delete cert with given friendly name");
            var filename = opts.AddVariable<string>("filename", "file to save");
            var pwd = opts.AddVariable<string>("password", "password to apply to saved cert");
            var help = opts.AddSwitch("help", "Show help");

            opts.Parse(args);
            if (help || string.IsNullOrEmpty(friendlyName.Value))
            {
                opts.WriteOptionDescriptions(Console.Out);
                Console.ReadKey();
                return;
            }

            CertificateHelper.FriendlyName = friendlyName.Value;
            if (delete)
            {
                CertificateHelper.DeleteCertificatesWithFriendlyName(friendlyName.Value);
            }
            else
            {
                var cert = CertificateHelper.GetClientCertificateByFriendlyName(friendlyName.Value);
                if (cert != null)
                {
                    if (string.IsNullOrEmpty(filename.Value))
                    {
                        Console.WriteLine($"Certificate with friendly name {friendlyName.Value} already exists");
                    }

                }
                else
                {
                    if (!CertificateHelper.CreateAndStoreSelfSignedCertificate(operatorName.Value, siteId.Value, seq.Value, server))
                    {
                        throw new System.Exception("could not create certficate!");
                    }
                    cert = CertificateHelper.GetClientCertificateByFriendlyName(friendlyName.Value);
                }

                if (!string.IsNullOrEmpty(filename.Value))
                {
                    //try to save cert...
                    byte[] certData = cert.Export(X509ContentType.Pfx, pwd.Value);
                    File.WriteAllBytes(filename.Value, certData);
                    Console.WriteLine($"saved file to {filename.Value}");
                }

                Console.WriteLine($"finished.  Cert thumbprint = {cert.Thumbprint}");
                Console.ReadKey();
            }

        }
    }

}
