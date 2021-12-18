using System;
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
                        };
                foreach (var s in usage)
                {
                    Console.WriteLine(s);
                }
                break;
        }
    }

    public static void sign(String filename, string password, string xmlFilename, string id, string signedXmlFilename)
    {
        try
        {
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.PreserveWhitespace = true;
            xmlDoc.Load(xmlFilename);
            XmlNodeList list = xmlDoc.SelectNodes(string.Format(@"//*[@id='{0}']", id));
            if (list.Count == 0)
            {
                return;
            }

            X509Certificate2 x509 = new X509Certificate2(filename, password, X509KeyStorageFlags.Exportable);
            SignXml(xmlDoc, x509, id);
            xmlDoc.Save(signedXmlFilename);
        }
        catch (Exception e)
        {
            Console.WriteLine(e.Message);
        }
    }

    public static void SignXml(XmlDocument xmlDoc, X509Certificate2 x509, string uri)
    {
        if (xmlDoc == null)
        {
            throw new ArgumentException("xmlDoc");
        }
        if (x509 == null)
        {
            throw new ArgumentException("x509");
        }

        PrefixedSignedXML signedXml = new PrefixedSignedXML(xmlDoc);
        signedXml.SigningKey = x509.GetRSAPrivateKey();
        signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
        signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;

        Reference reference = new Reference();
        reference.Uri = "#" + uri;

        XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
        reference.AddTransform(env);

        signedXml.AddReference(reference);

        KeyInfo keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(x509));
        signedXml.KeyInfo = keyInfo;

        signedXml.ComputeSignature("dsig");
        XmlElement xmlDigitalSignature = signedXml.GetXml();

        xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));
    }

    public static void verfy(string signedXmlFilename)
    {
        try
        {
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.PreserveWhitespace = true;
            xmlDoc.Load(signedXmlFilename);

            bool result = VerifyXml(xmlDoc);
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

    public static Boolean VerifyXml(XmlDocument Doc)
    {
        SignedXml signedXml = new SignedXml(Doc);
        XmlNodeList nodeList = Doc.GetElementsByTagName("Signature", "*");

        if (nodeList.Count <= 0)
        {
            throw new CryptographicException("Verification failed: No Signature was found in the document.");
        }
        if (nodeList.Count >= 2)
        {
            throw new CryptographicException("Verification failed: More that one signature was found for the document.");
        }
        XmlElement elm = (XmlElement)nodeList[0];
        signedXml.LoadXml(elm);
        return signedXml.CheckSignature();
    }
}
