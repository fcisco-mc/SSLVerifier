using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Net;

namespace SSLVerifier_s
{
    class Program
    {
        static void Main(string[] args)
        {

            if (args[0].Length.Equals(0))
            {
                Console.WriteLine("Please provide an input. E.g.: SSL_Verifier.exe www.outsystems.com");
                Console.ReadLine();

            } else
            {

                HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://" + args[0]);
                request.ServerCertificateValidationCallback = delegate { return true; };
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    X509Certificate2 cert2 = new X509Certificate2(request.ServicePoint.Certificate);

                    try
                    {
                        byte[] rawdata = cert2.RawData;
                        Console.WriteLine("Content Type: {0}{1}", X509Certificate2.GetCertContentType(rawdata), Environment.NewLine);
                        Console.WriteLine("Friendly Name: {0}{1}", cert2.FriendlyName, Environment.NewLine);
                        Console.WriteLine("Subject: {0}{1}", cert2.Subject, Environment.NewLine);
                        Console.WriteLine("Issuer Name: {0}{1}", cert2.GetIssuerName(), Environment.NewLine);
                        Console.WriteLine("Expiration: {0}{1}", cert2.GetExpirationDateString(), Environment.NewLine);
                        Console.WriteLine("Certificate Verified?: {0}{1}", cert2.Verify(), Environment.NewLine);
                        Console.WriteLine("Simple Name: {0}{1}", cert2.GetNameInfo(X509NameType.SimpleName, true), Environment.NewLine);
                        Console.WriteLine("Signature Algorithm: {0}{1}", cert2.SignatureAlgorithm.FriendlyName, Environment.NewLine);

                    }
                    catch (CryptographicException)
                    {
                        Console.WriteLine("Information could not be written out for this certificate.");
                    }

                    try
                    {
                        //Output chain information of the selected certificate.
                        X509Chain ch = new X509Chain();
                        ch.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                        ch.Build(cert2);

                        Console.WriteLine("Chain Information: ", cert2.RawData.Length, Environment.NewLine);
                        Console.WriteLine("Chain revocation flag: {0}", ch.ChainPolicy.RevocationFlag);
                        Console.WriteLine("Chain revocation mode: {0}", ch.ChainPolicy.RevocationMode);
                        Console.WriteLine("Chain verification flag: {0}", ch.ChainPolicy.VerificationFlags);
                        Console.WriteLine("Chain verification time: {0}", ch.ChainPolicy.VerificationTime);
                        Console.WriteLine("Chain status length: {0}", ch.ChainStatus.Length);
                        Console.WriteLine("Chain application policy count: {0}", ch.ChainPolicy.ApplicationPolicy.Count);
                        Console.WriteLine("Chain certificate policy count: {0} {1}", ch.ChainPolicy.CertificatePolicy.Count, Environment.NewLine);

                        //Output chain element information.
                        Console.WriteLine("Chain Element Information");
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
                    }

                    catch (CryptographicException)
                    {
                        Console.WriteLine("Error obtaining chain information");
                    }

                    Console.WriteLine("End of cryptographic test.");
                    Console.ReadLine();

                }
            }
        }
    }
}
