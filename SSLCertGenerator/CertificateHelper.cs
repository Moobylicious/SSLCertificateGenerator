using CERTENROLLLib;
using System;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;

namespace SSLCertGenerator
{
    class CertificateHelper
    {
        public static string FriendlyName = "HttpEasy";
        private static StoreLocation storeLoc = StoreLocation.LocalMachine;     // Store against machine, not user account
        private static StoreName store = StoreName.My;                          // Store as a personal certificate


        private static X509Certificate2 CreateSelfSignedCertificate(string Operator, string SiteId, int SeqNo, bool isServerCert, string SAN)
        {
            // Create a custom subject name & friendly name
            string distName = $"CN={FriendlyName.ToLower()}_{SiteId}_{SeqNo}, OU={Operator}_{SiteId}, O={Operator}, C=GB";

            // create DN for subject and issuer
            //            var dn = new X500DistinguishedName(distName);
            //            dn.Encode(distName, X500NameFlags.XCN_CERT_NAME_STR_NONE);
            var dn = new CX500DistinguishedName();            
            dn.Encode(distName, X500NameFlags.XCN_CERT_NAME_STR_NONE);


            // create a new private key for the certificate
            //CX509PrivateKey privateKey = new CX509PrivateKey();
            //var privateKey = new CX509PrivateKey();
            var typeName = "X509Enrollment.CX509PrivateKey";
            var type = Type.GetTypeFromProgID(typeName);
            if (type == null)
            {
                throw new Exception(typeName + " is not available on your system: 0x80040154 (REGDB_E_CLASSNOTREG)");
            }
            var privateKey = Activator.CreateInstance(type) as IX509PrivateKey;
            if (privateKey == null)
            {
                throw new Exception("Your certlib does not know an implementation of " + typeName +
                                    " (in HKLM:\\SOFTWARE\\Classes\\Interface\\)!");
            }
            privateKey.ProviderName = "Microsoft Base Cryptographic Provider v1.0";
            privateKey.MachineContext = true;
            privateKey.Length = 2048;
            privateKey.KeySpec = X509KeySpec.XCN_AT_SIGNATURE; // use is not limited
            // privateKey.ExportPolicy = X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
            privateKey.ExportPolicy = X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_EXPORT_FLAG;
            privateKey.Create();

            // Use the stronger SHA512 hashing algorithm
            var hashobj = new CObjectId();
            hashobj.InitializeFromAlgorithmName(ObjectIdGroupId.XCN_CRYPT_HASH_ALG_OID_GROUP_ID,
                ObjectIdPublicKeyFlags.XCN_CRYPT_OID_INFO_PUBKEY_ANY,
                AlgorithmFlags.AlgorithmFlagsNone, "SHA512");

            // add extended key usage if you want - look at MSDN for a list of possible OIDs
            var oid = new CObjectId();
            //            oid.InitializeFromValue("1.3.6.1.5.5.7.3.1"); // SSL server
            if (isServerCert)
            {
                oid.InitializeFromValue("1.3.6.1.5.5.7.3.1"); // SSL Server

            }
            else
            {
                oid.InitializeFromValue("1.3.6.1.5.5.7.3.2"); // SSL client
            }

            var oidlist = new CObjectIds();
            oidlist.Add(oid);
            var eku = new CX509ExtensionEnhancedKeyUsage();
            eku.InitializeEncode(oidlist);

            // Create the self signing request
            var cert = new CX509CertificateRequestCertificate();
            cert.InitializeFromPrivateKey(X509CertificateEnrollmentContext.ContextMachine, privateKey, "");

            if (!string.IsNullOrEmpty(SAN))
            {
                CAlternativeName objRfc822Name = new CAlternativeName();
                CAlternativeNames objAlternativeNames = new CAlternativeNames();
                CX509ExtensionAlternativeNames objExtensionAlternativeNames = new CX509ExtensionAlternativeNames();


                // Set Alternative RFC822 Name 
                objRfc822Name.InitializeFromString(AlternativeNameType.XCN_CERT_ALT_NAME_DNS_NAME, SAN);

                // Set Alternative Names 
                objAlternativeNames.Add(objRfc822Name);
                objExtensionAlternativeNames.InitializeEncode(objAlternativeNames);
                cert.X509Extensions.Add((CX509Extension)objExtensionAlternativeNames);
            }

            cert.Subject = dn;
            cert.Issuer = dn; // the issuer and the subject are the same
            cert.NotBefore = DateTime.Today;
            cert.NotAfter = DateTime.Today.AddYears(10);  // expire in 10 years time
            cert.X509Extensions.Add((CX509Extension)eku); // add the EKU
            cert.HashAlgorithm = hashobj; // Specify the hashing algorithm
            cert.Encode(); // encode the certificate

            // Do the final enrollment process
            var enroll = new CX509Enrollment();
            enroll.InitializeFromRequest(cert); // load the certificate
            enroll.CertificateFriendlyName = FriendlyName; // Optional: add a friendly name
            string csr = enroll.CreateRequest(); // Output the request in base64
                                                 // and install it back as the response
            enroll.InstallResponse(InstallResponseRestrictionFlags.AllowUntrustedCertificate,
                csr, EncodingType.XCN_CRYPT_STRING_BASE64, ""); // no password
                                                                // output a base64 encoded PKCS#12 so we can import it back to the .Net security classes
            var base64encoded = enroll.CreatePFX("", // no password, this is for internal consumption
                PFXExportOptions.PFXExportChainWithRoot);

            // instantiate the target class with the PKCS#12 data (and the empty password)
            X509Certificate2 newCert = new X509Certificate2(System.Convert.FromBase64String(base64encoded), "",
                                                           // mark the private key as exportable (this is usually what you want to do)
                                                           System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable
                                                           // Ensure the machine key is created and retained
                                                           // http://stackoverflow.com/questions/425688/how-to-set-read-permission-on-the-private-key-file-of-x-509-certificate-from-ne
                                                           | X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);

            return newCert;
        }


        /// <summary>
        /// A private key file will have been stored in C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys
        /// We need to make sure the current user has permissions to access it
        /// </summary>
        /// <param name="certificate"></param>
        private static void SetKeyPermissions(X509Certificate2 certificate)
        {

            // Now set read permissions to access the certificate's private key
            // http://stackoverflow.com/questions/425688/how-to-set-read-permission-on-the-private-key-file-of-x-509-certificate-from-ne
            var rsa = certificate.PrivateKey as RSACryptoServiceProvider;
            if (rsa != null)
            {
                // Modifying the CryptoKeySecurity of a new CspParameters and then instantiating
                // a new RSACryptoServiceProvider seems to be the trick to persist the access rule.
                // cf. http://blogs.msdn.com/b/cagatay/archive/2009/02/08/removing-acls-from-csp-key-containers.aspx
                var cspParams = new CspParameters(rsa.CspKeyContainerInfo.ProviderType, rsa.CspKeyContainerInfo.ProviderName, rsa.CspKeyContainerInfo.KeyContainerName)
                {
                    //                    Flags = CspProviderFlags.UseExistingKey | CspProviderFlags.UseMachineKeyStore,
                    Flags = CspProviderFlags.UseMachineKeyStore,
                    CryptoKeySecurity = rsa.CspKeyContainerInfo.CryptoKeySecurity
                };

                cspParams.CryptoKeySecurity.AddAccessRule(new CryptoKeyAccessRule(new NTAccount(WindowsIdentity.GetCurrent().Name), CryptoKeyRights.GenericRead, AccessControlType.Allow));

                using (var rsa2 = new RSACryptoServiceProvider(cspParams))
                {
                    // Only created to persist the rule change in the CryptoKeySecurity
                }
            }
        }

        /// <summary>
        /// Save the certificate to the certificates store
        /// </summary>
        /// <param name="newCertificate"></param>
        /// <returns></returns>
        private static bool StoreSelfSignedCertificate(X509Certificate2 newCertificate)
        {
            // Delete any previous certificates with same friendly name
            DeleteCertificatesWithFriendlyName(FriendlyName);

            X509Store userCaStore = new X509Store(store, storeLoc);
            try
            {
                userCaStore.Open(OpenFlags.ReadWrite);
                userCaStore.Add(newCertificate);

                // Apply permissions for current user to access it
                SetKeyPermissions(newCertificate);

                return true;
            }
            catch
            {
                throw;
            }
            finally
            {
                userCaStore.Close();
            }

            // Create an external certificate file?
            //  File.WriteAllBytes("c://Test.cer", newCertificate.Export(X509ContentType.Cert));
        }

        public static bool CreateAndStoreServerSelfSignedCertificate(string friendlyName, string siteurl)
        {
            FriendlyName = friendlyName;
            X509Certificate2 Cert = CreateSelfSignedCertificate(friendlyName.Replace(" ",""), "0", 1, true, siteurl);
            if (Cert == null)
                return false;
            else
                return StoreSelfSignedCertificate(Cert);

        }

        public static bool CreateAndStoreSelfSignedCertificate(string Operator, string SiteId, int SeqNo, bool isServerCert)
        {
            X509Certificate2 Cert = CreateSelfSignedCertificate(Operator, SiteId, SeqNo, isServerCert, string.Empty);
            if (Cert == null)
                return false;
            else
                return StoreSelfSignedCertificate(Cert);
        }


        public static X509Certificate2 GetClientCertificateBySubjectName(string subjectName)
        {
            X509Store userCaStore = new X509Store(store, storeLoc);
            try
            {
                userCaStore.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certificatesInStore = userCaStore.Certificates;
                X509Certificate2Collection findResult = certificatesInStore.Find(X509FindType.FindBySubjectName, subjectName, true);
                X509Certificate2 clientCertificate = null;
                if (findResult.Count == 1)
                {
                    clientCertificate = findResult[0];
                }
                return clientCertificate;
            }
            catch
            {
                throw;
            }
            finally
            {
                userCaStore.Close();
            }
        }


        public static X509Certificate2 GetClientCertificateByFriendlyName(string friendlyName)
        {
            X509Store userCaStore = new X509Store(store, storeLoc);
            try
            {
                userCaStore.Open(OpenFlags.ReadOnly);
                var certificates = userCaStore.Certificates;
                foreach (var certificate in certificates)
                {
                    if (certificate.FriendlyName == friendlyName)
                    {
                        return certificate;
                    }
                }
                return null;
            }
            catch
            {
                throw;
            }
            finally
            {
                userCaStore.Close();
            }
        }


        public static bool VerifyCertificate(string friendlyName)
        {
            X509Certificate2 Cert = GetClientCertificateByFriendlyName(friendlyName);
            if (Cert == null)
                return false;

            return VerifyCertificate(Cert);
        }

        public static bool VerifyCertificate(X509Certificate2 certificate)
        {
            //            return certificate.Verify();

            X509Chain ch = new X509Chain();
            ch.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            ch.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            ch.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            bool IsCertificateChainValid = ch.Build(certificate);

            if (!IsCertificateChainValid)
            {
                /*                Console.WriteLine("Certificate chain is not valid");
                                Console.WriteLine("Number of chain elements: {0}", ch.ChainElements.Count);
                                Console.WriteLine("Chain elements synchronized? {0} {1}", ch.ChainElements.IsSynchronized, Environment.NewLine);

                                foreach (X509ChainElement element in ch.ChainElements)
                                {
                                    Console.WriteLine("Element issuer name: {0}", element.Certificate.Issuer);
                                    Console.WriteLine("Element certificate valid until: {0}", element.Certificate.NotAfter);
                                    Console.WriteLine("Element certificate is valid: {0}", element.Certificate.Verify());
                                    Console.WriteLine("Element error status length: {0}", element.ChainElementStatus.Length);
                                    Console.WriteLine("Element information: {0}", element.Information);
                                    Console.WriteLine("Number of element extensions: {0}{1}", element.Certificate.Extensions.Count, Environment.NewLine);

                                    if (ch.ChainStatus.Length > 1)
                                    {
                                        for (int index = 0; index < element.ChainElementStatus.Length; index++)
                                        {
                                            Console.WriteLine(element.ChainElementStatus[index].Status);
                                            Console.WriteLine(element.ChainElementStatus[index].StatusInformation);
                                        }
                                    }
                                }
                */

                foreach (X509ChainStatus objChainStatus in ch.ChainStatus)
                    Console.WriteLine(objChainStatus.Status.ToString() + " - " + objChainStatus.StatusInformation);

            }
            return IsCertificateChainValid;
        }



        public static void DeleteCertificatesWithFriendlyName(string friendlyName)
        {
            X509Store userCaStore = new X509Store(store, storeLoc);
            try
            {
                userCaStore.Open(OpenFlags.ReadWrite);

                // Remove any existing certificate with same name
                var certificates = userCaStore.Certificates;
                foreach (var certificate in certificates)
                {
                    if (certificate.FriendlyName == friendlyName)
                        userCaStore.Remove(certificate);
                }
            }
            finally
            {
                userCaStore.Close();
            }
        }

    }
}
