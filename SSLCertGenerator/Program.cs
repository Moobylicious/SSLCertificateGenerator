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
            var delete = opts.AddSwitch("delete", "delete cert/rules with given friendly name/acl");
            var filename = opts.AddVariable<string>("filename", "file to save");
            var pwd = opts.AddVariable<string>("password", "password to apply to saved cert");
            var help = opts.AddSwitch("help", "Show help");

            var acl = opts.AddVariable<string>("urlacl", "urlAcl rule to add in form of hostname:port.  e.g. \"quantumApi:4433\"");

            opts.Parse(args);
            if (help || string.IsNullOrEmpty(friendlyName.Value))
            {
                opts.WriteOptionDescriptions(Console.Out);
                Console.ReadKey();
                return;
            }

            CertificateHelper.FriendlyName = friendlyName.Value;
            var cert = CertificateHelper.GetClientCertificateByFriendlyName(friendlyName.Value);
            if (!delete)
            {
                if (cert != null)
                {
                    if (string.IsNullOrEmpty(filename.Value))
                    {
                        Console.WriteLine($"Certificate with friendly name {friendlyName.Value} already exists");
                    }
                }
                else
                {
                    var urlOnly = acl.Value;
                    if (!string.IsNullOrEmpty(urlOnly) && (urlOnly.IndexOf(":") > 0))
                    {
                        urlOnly = urlOnly.Substring(0, urlOnly.IndexOf(":"));
                    };
                    if (
                        (server && !CertificateHelper.CreateAndStoreServerSelfSignedCertificate(friendlyName.Value, urlOnly))
                        || (!server && !CertificateHelper.CreateAndStoreSelfSignedCertificate(operatorName.Value, siteId.Value, seq.Value, server))
                        )
                    {
                        throw new System.Exception("could not create certficate!");
                    }
                    cert = CertificateHelper.GetClientCertificateByFriendlyName(friendlyName.Value);
                }
            }

            if (!string.IsNullOrEmpty(acl.Value))
            {
                //add sslcert 
                //Generate App guid.
                var appGuid = Guid.NewGuid();
                System.Diagnostics.Process process = new System.Diagnostics.Process();
                System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
                startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
                startInfo.FileName = "cmd.exe";
                if (!delete)
                {
                    Console.WriteLine($"Attempting to add sslcert rule with app id {appGuid.ToString()}");
                    var cmdargs = $"/C netsh http add sslcert hostnameport={acl.Value} appid={{\"{appGuid.ToString()}\"}} certhash={cert.Thumbprint} certstorename=MY";
                    Console.WriteLine(cmdargs);
                    startInfo.Arguments = cmdargs;
                }
                else
                {
                    Console.WriteLine($"Attempting to delete sslcert rule {acl.Value}");
                    startInfo.Arguments = $"/C netsh http delete sslcert hostnameport={acl.Value}";
                }

                startInfo.RedirectStandardError = true;
                startInfo.RedirectStandardOutput = true;
                startInfo.UseShellExecute = false;
                process.StartInfo = startInfo;

                process.Start();
                Console.WriteLine("Waiting for process....");
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();

                process.WaitForExit();
                Console.WriteLine($"Process finished (exit code = {process.ExitCode})");
                Console.WriteLine(output);
                Console.WriteLine(error);


                // now we add a urlACL rule...
                process = new System.Diagnostics.Process();
                startInfo = new System.Diagnostics.ProcessStartInfo();
                startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
                startInfo.FileName = "cmd.exe";
                if (!delete)
                {
                    Console.WriteLine($"Attempting to add urlACL rule for https://{acl.Value}/");
                    var cmdargs = $"/C netsh http add urlacl url=https://{acl.Value}/ user=EVERYONE";
                    Console.WriteLine(cmdargs);
                    startInfo.Arguments = cmdargs;
                }
                else
                {
                    Console.WriteLine($"Attempting to delete urlacl rule {acl.Value}");
                    startInfo.Arguments = $"/C netsh http delete urlacl url=https://{acl.Value}/";
                }
                startInfo.RedirectStandardError = true;
                startInfo.RedirectStandardOutput = true;
                startInfo.UseShellExecute = false;
                process.StartInfo = startInfo;
                process.Start();
                Console.WriteLine("Waiting for process....");
                output = process.StandardOutput.ReadToEnd();
                error = process.StandardError.ReadToEnd();
                process.WaitForExit();
                Console.WriteLine($"Process finished (exit code = {process.ExitCode})");
                Console.WriteLine(output);
                Console.WriteLine(error);

                //try to save cert for adding to clients as a 'trusted doohickey'
                if (!delete)
                {
                    if (File.Exists($"{friendlyName.Value}.pfx"))
                    {
                        File.Delete($"{friendlyName.Value}.pfx");
                    }
                    var pwdGuid = Guid.NewGuid().ToString().Replace("{", "").Replace("}", "").Replace("-", "").Substring(0, 8);
                    byte[] certData = cert.Export(X509ContentType.Pfx, pwdGuid);
                    File.WriteAllBytes($"{friendlyName.Value}.pfx", certData);

                    File.WriteAllText("pass.txt", pwdGuid);

                    Console.WriteLine($"saved file to {friendlyName.Value}.pfx - add this to Trusted providers on clients (password is {pwdGuid}), saved to pass.txt");

                }
            }
            else if (!string.IsNullOrEmpty(filename.Value) && !delete)
            {
                //try to save cert...
                byte[] certData = cert.Export(X509ContentType.Pfx, pwd.Value);
                File.WriteAllBytes(filename.Value, certData);
                Console.WriteLine($"saved file to {filename.Value}");
            }

            Console.WriteLine($"finished.  Cert thumbprint = {cert?.Thumbprint ?? "n/a"} saved to thumbprint.txt");
            if (cert != null)
            {
                File.WriteAllText("thumbprint.txt", cert.Thumbprint);
            }           
            //Console.ReadKey();

            if (delete)
            {
                CertificateHelper.DeleteCertificatesWithFriendlyName(friendlyName.Value);
            }
        }
        
    }

}
