using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using VerfySignedXML;

public class VerifySignedXML
{
    // 引数
    //  １：PKCS12ファイル
    //  ２：パスワード
    //  ３：署名前XMLファイル（入力）
    //  ４：署名付与対象（ID属性の値）
    //  ５：署名済XMLファイル（出力）
    public static void Main(String[] args)
    {
        switch (args.Length)
        {
            case 1:
                // 署名検証
                verfy(args[0]);
                break;

            case 2:
                // 証明書情報取得
                getSigInfo(args[0], args[1]);
                break;

            case 3:
                // ダイジェスト値生成
                TRANSFORM_KIND trfKind = TRANSFORM_KIND.DsigC14NTransform;
                if (TRANSFORM_KIND_ARGS.ContainsKey(args[1]))
                {
                    trfKind = TRANSFORM_KIND_ARGS[args[1]];
                }
                DIGEST_KIND digestKind = DIGEST_KIND.SHA256;
                if (DIGEST_KIND_ARGS.ContainsKey(args[2]))
                {
                    digestKind = DIGEST_KIND_ARGS[args[2]];
                }

                string result = makeDigestValue(args[0], trfKind, digestKind);
                Console.WriteLine(result);
                break;

            case 5:
                // 署名付与→署名検証
                sign(args[0], args[1], args[2], args[3], args[4]);
                verfy(args[4]);
                break;

            default:
                // Usage
                string[] usage = {
                    "署名付与・検証ツール",
                    "usage:",
                    "\t署名付与：>.\\VerfySignedXML.exe <PKCS12ファイル名> <PKCS12パスワード> <署名対象XMLファイル名> <署名付与対象ID属性値> <出力ファイル名>",
                    "\t署名検証：>.\\VerfySignedXML.exe <署名検証XMLファイル>",
                    "\tダイジェスト値：>.\\VerfySignedXML.exe <署名検証XMLファイル> [DSIGC14|DSIGEXECC14] [SHA1|SHA256|SHA384|SHA512]",
                    "\t証明書情報取得：>.\\VerfySignedXML.exe <PKCS12ファイル名> <PKCS12パスワード>",
                        };
                foreach (var s in usage)
                {
                    Console.WriteLine(s);
                }
                break;
        }
    }

    private static void getSigInfo(String filename, string password)
    {
        try
        {
            var x509 = new X509Certificate2(filename, password, X509KeyStorageFlags.Exportable);
            dispPropertyValue(x509);
        }
        catch (Exception e)
        {
            Console.WriteLine(e.Message);
        }
    }
    private static void dispPropertyValue(X509Certificate2 x509)
    {
        Console.WriteLine("Archived={0}", x509.Archived);
        Console.WriteLine("FriendlyName={0}", x509.FriendlyName);
        Console.WriteLine("HasPrivateKey={0}", x509.HasPrivateKey);
        Console.WriteLine("Issuer={0}", x509.Issuer);
        Console.WriteLine("IssuerName={0}", x509.IssuerName);
        Console.WriteLine("NotAfter={0}", x509.NotAfter);
        Console.WriteLine("NotBefore={0}", x509.NotBefore);

        Console.WriteLine("PublicKey={0}", x509.PublicKey.ToString());

        Console.WriteLine("SerialNumber={0}", x509.SerialNumber);
        //Console.WriteLine("SignatureAlgorithm={0}", x509.SignatureAlgorithm);
        Console.WriteLine("SignatureAlgorithm.FriendlyName={0}", x509.SignatureAlgorithm.FriendlyName);
        Console.WriteLine("SignatureAlgorithm.Value={0}", x509.SignatureAlgorithm.Value);
        Console.WriteLine("Subject={0}", x509.Subject);
        Console.WriteLine("SubjectName={0}", x509.SubjectName);
        Console.WriteLine("Thumbprint={0}", x509.Thumbprint);
        Console.WriteLine("Version={0}", x509.Version);

        Console.WriteLine("KeyExchangeAlgorithm={0}", x509.PrivateKey.KeyExchangeAlgorithm);
        Console.WriteLine("KeySize={0}", x509.PrivateKey.KeySize);
        foreach (var item in x509.PrivateKey.LegalKeySizes)
        {
            Console.WriteLine("PrivateKey.LegalKeySizes={0}", item.MaxSize);
            Console.WriteLine("PrivateKey.LegalKeySizes={0}", item.MinSize);
            Console.WriteLine("PrivateKey.LegalKeySizes={0}", item.SkipSize);
        }

        Console.WriteLine("PublicKey.EncodedKeyValue.Oid.FriendlyName={0}", x509.PublicKey.EncodedKeyValue.Oid.FriendlyName);
        Console.WriteLine("PublicKey.EncodedKeyValue.Value={0}", x509.PublicKey.EncodedKeyValue);
        Console.Write("PublicKey.EncodedKeyValue.RawData=");
        dispRowData(x509.PublicKey.EncodedKeyValue.RawData);

        Console.WriteLine("PublicKey.EncodedParameters.Oid.FriendlyName={0}", x509.PublicKey.EncodedParameters.Oid.FriendlyName);
        Console.WriteLine("PublicKey.EncodedParameters.Value={0}", x509.PublicKey.EncodedParameters);
        Console.Write("PublicKey.EncodedParameters.RawData=");
        dispRowData(x509.PublicKey.EncodedParameters.RawData);

        Console.WriteLine("SubjectName.Name={0}", x509.SubjectName.Name);
        Console.WriteLine("SubjectName.Oid.FriendlyName={0}", x509.SubjectName.Oid.FriendlyName);
        Console.WriteLine("SubjectName.Oid.Value={0}", x509.SubjectName.Oid.Value);
        Console.Write("SubjectName.RawData=");
        dispRowData(x509.SubjectName.RawData);

        Console.Write("RawData=");
        dispRowData(x509.RawData);

        Console.WriteLine("SignatureAlgorith={0}", x509.PrivateKey.SignatureAlgorithm);

    }
    private static void dispRowData(byte[] data)
    {
        foreach (var d in data) {
            Console.Write("{0:X2}", d);
        }
        Console.WriteLine("");
    }

    enum TRANSFORM_KIND
    {
        DsigC14NTransform,
        DsigExcC14NTransform,
    };
    static Dictionary<string, TRANSFORM_KIND> TRANSFORM_KIND_ARGS = new Dictionary<string, TRANSFORM_KIND>{
        { "DSIGC14", TRANSFORM_KIND.DsigC14NTransform},
        { "DSIGEXECC14", TRANSFORM_KIND.DsigExcC14NTransform},
    };

    enum DIGEST_KIND
    {
        //MD5,
        SHA1,
        SHA256,
        SHA384,
        SHA512,
    }
    static Dictionary<string, DIGEST_KIND> DIGEST_KIND_ARGS = new Dictionary<string, DIGEST_KIND>{
        { "SHA1", DIGEST_KIND.SHA1},
        { "SHA256", DIGEST_KIND.SHA256},
        { "SHA384", DIGEST_KIND.SHA384},
        { "SHA512", DIGEST_KIND.SHA512},
    };
    // test
    private static string makeDigestValue(string xmlFilename, TRANSFORM_KIND trnsFrmKind, DIGEST_KIND digestKind)
    {
        string base64Val = "";
        try
        {
            var xmlDoc = new XmlDocument();
            xmlDoc.PreserveWhitespace = true;
            xmlDoc.Load(xmlFilename);

            var trnsfDES = new XmlDsigEnvelopedSignatureTransform();
            trnsfDES.Algorithm = SignedXml.XmlDsigEnvelopedSignatureTransformUrl;
            var elm = trnsfDES.GetXml();
            trnsfDES.LoadInput(xmlDoc);
            XmlDocument xmlDocumentOutput = (XmlDocument)trnsfDES.GetOutput(typeof(XmlDocument));

            // XMLの正規化 canonicalization
            Transform trnsf;
            switch (trnsFrmKind)
            {
                case TRANSFORM_KIND.DsigExcC14NTransform:
                    trnsf = new XmlDsigExcC14NTransform();  // http://www.w3.org/2001/10/xml-exc-c14n#
                    break;
                case TRANSFORM_KIND.DsigC14NTransform:
                default:
                    trnsf = new XmlDsigC14NTransform(); // http://www.w3.org/TR/2001/REC-xml-c14n-20010315
                    break;
            }

            trnsf.LoadInput(xmlDocumentOutput);
            var ms = (MemoryStream)trnsf.GetOutput(typeof(CryptoStream));
            //Console.WriteLine("[" + Encoding.UTF8.GetString(ms.ToArray()) +"]");

            // ハッシュ値算出：SHA1
            HashAlgorithm hashM;
            switch (digestKind)
            {
                case DIGEST_KIND.SHA1:
                    hashM = SHA1.Create();
                    // 以下も同じ
                    //new SHA1Cng();
                    //new SHA1CryptoServiceProvider();
                    break;
                case DIGEST_KIND.SHA384:
                    hashM = SHA384.Create();
                    break;
                case DIGEST_KIND.SHA512:
                    hashM = SHA512.Create();
                    break;
                case DIGEST_KIND.SHA256:
                default:
                    hashM = SHA256.Create();
                    break;
            }

            var hashVal = hashM.ComputeHash(ms);
            base64Val = Convert.ToBase64String(hashVal);
            //Console.WriteLine(base64Val);
        }
        catch (Exception e)
        {
            Console.WriteLine(e.Message);
        }

        return base64Val;
    }


    private static void sign(String filename, string password, string xmlFilename, string id, string signedXmlFilename)
    {
        try
        {
            var xmlDoc = new XmlDocument();
            xmlDoc.PreserveWhitespace = true;
            xmlDoc.Load(xmlFilename);
            var list = xmlDoc.SelectNodes(string.Format(@"//*[@id='{0}']", id));
            if (list.Count == 0)
            {
                Console.WriteLine("No Exists spacify id.");
                return;
            }

            var x509 = new X509Certificate2(filename, password, X509KeyStorageFlags.Exportable);
            var signedXml = SignXml(xmlDoc, x509, id);

            list.Item(list.Count - 1).AppendChild(xmlDoc.ImportNode(signedXml, true));

            xmlDoc.Save(signedXmlFilename);
        }
        catch (Exception e)
        {
            Console.WriteLine(e.Message);
        }
    }

    private static XmlElement SignXml(XmlDocument xmlDoc, X509Certificate2 x509, string uri)
    {
        if (xmlDoc == null)
        {
            throw new ArgumentException("xmlDoc");
        }
        if (x509 == null)
        {
            throw new ArgumentException("x509");
        }

        var signedXml = new PrefixedSignedXML(xmlDoc);
        signedXml.SigningKey = x509.GetRSAPrivateKey();
        signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
        signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;

        var reference = new Reference();
        reference.Uri = "#" + uri;

        var env = new XmlDsigEnvelopedSignatureTransform();
        reference.AddTransform(env);

        signedXml.AddReference(reference);

        var keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(x509));
        signedXml.KeyInfo = keyInfo;

        signedXml.ComputeSignature("dsig");
        return signedXml.GetXml();
    }

    private static void verfy(string signedXmlFilename)
    {
        try
        {
            var xmlDoc = new XmlDocument();
            xmlDoc.PreserveWhitespace = true;
            xmlDoc.Load(signedXmlFilename);

            var result = VerifyXml(xmlDoc);
            if (result)
            {
                Console.WriteLine("The XML signature is valid.");
            }
            else
            {
                Console.WriteLine("The XML signature is not valid.");
            }

        }
        catch (Exception e)
        {
            Console.WriteLine(e.Message);
        }
    }

    private static Boolean VerifyXml(XmlDocument Doc)
    {
        var signedXml = new SignedXml(Doc);
        var nodeList = Doc.GetElementsByTagName("Signature", "*");

        if (nodeList.Count <= 0)
        {
            throw new CryptographicException("Verification failed: No Signature was found in the document.");
        }
        if (nodeList.Count >= 2)
        {
            throw new CryptographicException("Verification failed: More that one signature was found for the document.");
        }
        var elm = (XmlElement)nodeList[0];
        signedXml.LoadXml(elm);
        var rtn = signedXml.CheckSignature();

        var x509certList = Doc.GetElementsByTagName("X509Certificate", "*");
        var x509certText = x509certList[0].InnerText;
        var x = new X509Certificate2(Convert.FromBase64String(x509certText));
        var ch = new X509Chain();
        //ch.ChainPolicy.RevocationMode = X509RevocationMode.Online;
        ch.ChainPolicy.RevocationMode = X509RevocationMode.Offline;
        //ch.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
        var isChainOK = ch.Build(x);
        Console.WriteLine("Chain Build {0}", isChainOK);

        //Console.WriteLine("Chain Information");
        //Console.WriteLine("Chain revocation flag: {0}", ch.ChainPolicy.RevocationFlag);
        //Console.WriteLine("Chain revocation mode: {0}", ch.ChainPolicy.RevocationMode);
        //Console.WriteLine("Chain verification flag: {0}", ch.ChainPolicy.VerificationFlags);
        //Console.WriteLine("Chain verification time: {0}", ch.ChainPolicy.VerificationTime);
        //Console.WriteLine("Chain status length: {0}", ch.ChainStatus.Length);
        //Console.WriteLine("Chain application policy count: {0}", ch.ChainPolicy.ApplicationPolicy.Count);
        //Console.WriteLine("Chain certificate policy count: {0} {1}", ch.ChainPolicy.CertificatePolicy.Count, Environment.NewLine);

        ////Output chain element information.
        //Console.WriteLine("Chain Element Information");
        //Console.WriteLine("Number of chain elements: {0}", ch.ChainElements.Count);
        //Console.WriteLine("Chain elements synchronized? {0} {1}", ch.ChainElements.IsSynchronized, Environment.NewLine);

        //foreach (X509ChainElement element in ch.ChainElements)
        //{
        //    Console.WriteLine("Element issuer name: {0}", element.Certificate.Issuer);
        //    Console.WriteLine("Element certificate valid until: {0}", element.Certificate.NotAfter);
        //    Console.WriteLine("Element certificate is valid: {0}", element.Certificate.Verify());
        //    Console.WriteLine("Element error status length: {0}", element.ChainElementStatus.Length);
        //    Console.WriteLine("Element information: {0}", element.Information);
        //    Console.WriteLine("Number of element extensions: {0}{1}", element.Certificate.Extensions.Count, Environment.NewLine);

        //    if (ch.ChainStatus.Length > 1)
        //    {
        //        for (int index = 0; index < element.ChainElementStatus.Length; index++)
        //        {
        //            Console.WriteLine(element.ChainElementStatus[index].Status);
        //            Console.WriteLine(element.ChainElementStatus[index].StatusInformation);
        //        }
        //    }
        //}

        return rtn;
    }
}
