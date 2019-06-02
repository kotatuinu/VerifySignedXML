// https://stackoverflow.com/questions/12219232/xml-signature-ds-prefix
using System;
using System.Reflection;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography;
using System.Xml;

namespace VerfySignedXML
{
    public class PrefixedSignedXML : SignedXml
    {
        public PrefixedSignedXML(XmlDocument document)
            : base(document)
        { }

        public PrefixedSignedXML(XmlElement element)
            : base(element)
        { }

        public PrefixedSignedXML()
            : base()
        { }

        public string prefix { get; private set; }

        public new void ComputeSignature()
        {
            prefix = "";
            base.ComputeSignature();
        }
        public void ComputeSignature(string prefix)
        {
            this.BuildDigestedReferences();
            AsymmetricAlgorithm signingKey = this.SigningKey;
            if (signingKey == null)
            {
                throw new CryptographicException("Cryptography_Xml_LoadKeyFailed");
            }
            if (this.SignedInfo.SignatureMethod == null)
            {
                if (!(signingKey is DSA))
                {
                    if (!(signingKey is RSA))
                    {
                        throw new CryptographicException("Cryptography_Xml_CreatedKeyFailed");
                    }
                    if (this.SignedInfo.SignatureMethod == null)
                    {
                        this.SignedInfo.SignatureMethod = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
                    }
                }
                else
                {
                    this.SignedInfo.SignatureMethod = "http://www.w3.org/2000/09/xmldsig#dsa-sha1";
                }
            }
            SignatureDescription description = CryptoConfig.CreateFromName(this.SignedInfo.SignatureMethod) as SignatureDescription;
            if (description == null)
            {
                throw new CryptographicException("Cryptography_Xml_SignatureDescriptionNotCreated");
            }
            HashAlgorithm hash = description.CreateDigest();
            if (hash == null)
            {
                throw new CryptographicException("Cryptography_Xml_CreateHashAlgorithmFailed");
            }
            this.GetC14NDigest(hash, prefix);
            this.m_signature.SignatureValue = description.CreateFormatter(signingKey).CreateSignature(hash);
            this.prefix = prefix;
        }

        public new XmlElement GetXml()
        {
            XmlElement e = base.GetXml();
            SetPrefix(prefix, e);
            return e;
        }

        private void BuildDigestedReferences()
        {
            Type t = typeof(SignedXml);
            MethodInfo m = t.GetMethod("BuildDigestedReferences", BindingFlags.NonPublic | BindingFlags.Instance);
            m.Invoke(this, new object[] { });
        }

        private byte[] GetC14NDigest(HashAlgorithm hash, string prefix)
        {
            XmlDocument document = new XmlDocument();
            document.PreserveWhitespace = true;
            XmlElement e = this.SignedInfo.GetXml();
            document.AppendChild(document.ImportNode(e, true));

            Transform canonicalizationMethodObject = this.SignedInfo.CanonicalizationMethodObject;
            SetPrefix(prefix, document.DocumentElement);
             canonicalizationMethodObject.LoadInput(document);
            return canonicalizationMethodObject.GetDigestedOutput(hash);
        }

        private void SetPrefix(string prefix, XmlNode node)
        {
            foreach (XmlNode n in node.ChildNodes)
                SetPrefix(prefix, n);
            node.Prefix = prefix;
        }
    }
}
