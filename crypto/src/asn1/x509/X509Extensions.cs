using System;
using System.Collections.Generic;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Asn1.X509
{
    public class X509Extensions
        : Asn1Encodable
    {
		/**
		 * Subject Directory Attributes
		 */
		public static readonly DerObjectIdentifier SubjectDirectoryAttributes = new DerObjectIdentifier("2.5.29.9");

		/**
         * Subject Key Identifier
         */
        public static readonly DerObjectIdentifier SubjectKeyIdentifier = new DerObjectIdentifier("2.5.29.14");

		/**
         * Key Usage
         */
        public static readonly DerObjectIdentifier KeyUsage = new DerObjectIdentifier("2.5.29.15");

		/**
         * Private Key Usage Period
         */
        public static readonly DerObjectIdentifier PrivateKeyUsagePeriod = new DerObjectIdentifier("2.5.29.16");

		/**
         * Subject Alternative Name
         */
        public static readonly DerObjectIdentifier SubjectAlternativeName = new DerObjectIdentifier("2.5.29.17");

		/**
         * Issuer Alternative Name
         */
        public static readonly DerObjectIdentifier IssuerAlternativeName = new DerObjectIdentifier("2.5.29.18");

		/**
         * Basic Constraints
         */
        public static readonly DerObjectIdentifier BasicConstraints = new DerObjectIdentifier("2.5.29.19");

		/**
         * CRL Number
         */
        public static readonly DerObjectIdentifier CrlNumber = new DerObjectIdentifier("2.5.29.20");

		/**
         * Reason code
         */
        public static readonly DerObjectIdentifier ReasonCode = new DerObjectIdentifier("2.5.29.21");

		/**
         * Hold Instruction Code
         */
        public static readonly DerObjectIdentifier InstructionCode = new DerObjectIdentifier("2.5.29.23");

		/**
         * Invalidity Date
         */
        public static readonly DerObjectIdentifier InvalidityDate = new DerObjectIdentifier("2.5.29.24");

		/**
         * Delta CRL indicator
         */
        public static readonly DerObjectIdentifier DeltaCrlIndicator = new DerObjectIdentifier("2.5.29.27");

		/**
         * Issuing Distribution Point
         */
        public static readonly DerObjectIdentifier IssuingDistributionPoint = new DerObjectIdentifier("2.5.29.28");

		/**
         * Certificate Issuer
         */
        public static readonly DerObjectIdentifier CertificateIssuer = new DerObjectIdentifier("2.5.29.29");

		/**
         * Name Constraints
         */
        public static readonly DerObjectIdentifier NameConstraints = new DerObjectIdentifier("2.5.29.30");

		/**
         * CRL Distribution Points
         */
        public static readonly DerObjectIdentifier CrlDistributionPoints = new DerObjectIdentifier("2.5.29.31");

		/**
         * Certificate Policies
         */
        public static readonly DerObjectIdentifier CertificatePolicies = new DerObjectIdentifier("2.5.29.32");

		/**
         * Policy Mappings
         */
        public static readonly DerObjectIdentifier PolicyMappings = new DerObjectIdentifier("2.5.29.33");

		/**
         * Authority Key Identifier
         */
        public static readonly DerObjectIdentifier AuthorityKeyIdentifier = new DerObjectIdentifier("2.5.29.35");

		/**
         * Policy Constraints
         */
        public static readonly DerObjectIdentifier PolicyConstraints = new DerObjectIdentifier("2.5.29.36");

		/**
         * Extended Key Usage
         */
        public static readonly DerObjectIdentifier ExtendedKeyUsage = new DerObjectIdentifier("2.5.29.37");

		/**
		 * Freshest CRL
		 */
		public static readonly DerObjectIdentifier FreshestCrl = new DerObjectIdentifier("2.5.29.46");

		/**
         * Inhibit Any Policy
         */
        public static readonly DerObjectIdentifier InhibitAnyPolicy = new DerObjectIdentifier("2.5.29.54");

		/**
         * Authority Info Access
         */
		public static readonly DerObjectIdentifier AuthorityInfoAccess = X509ObjectIdentifiers.IdPE.Branch("1");

        /**
		 * BiometricInfo
		 */
        public static readonly DerObjectIdentifier BiometricInfo = X509ObjectIdentifiers.IdPE.Branch("2");

        /**
		 * QCStatements
		 */
        public static readonly DerObjectIdentifier QCStatements = X509ObjectIdentifiers.IdPE.Branch("3");

        /**
		 * Audit identity extension in attribute certificates.
		 */
        public static readonly DerObjectIdentifier AuditIdentity = X509ObjectIdentifiers.IdPE.Branch("4");

        /**
		 * Subject Info Access
		 */
        public static readonly DerObjectIdentifier SubjectInfoAccess = X509ObjectIdentifiers.IdPE.Branch("11");

        /**
		 * Logo Type
		 */
        public static readonly DerObjectIdentifier LogoType = X509ObjectIdentifiers.IdPE.Branch("12");

        /**
		 * NoRevAvail extension in attribute certificates.
		 */
        public static readonly DerObjectIdentifier NoRevAvail = new DerObjectIdentifier("2.5.29.56");

		/**
		 * TargetInformation extension in attribute certificates.
		 */
		public static readonly DerObjectIdentifier TargetInformation = new DerObjectIdentifier("2.5.29.55");

        /**
         * Expired Certificates on CRL extension
         */
        public static readonly DerObjectIdentifier ExpiredCertsOnCrl = new DerObjectIdentifier("2.5.29.60");

        /**
         * the subject�s alternative public key information
         */
        public static readonly DerObjectIdentifier SubjectAltPublicKeyInfo = new DerObjectIdentifier("2.5.29.72");

        /**
         * the algorithm identifier for the alternative digital signature algorithm.
         */
        public static readonly DerObjectIdentifier AltSignatureAlgorithm = new DerObjectIdentifier("2.5.29.73");

        /**
         * alternative signature shall be created by the issuer using its alternative private key.
         */
        public static readonly DerObjectIdentifier AltSignatureValue = new DerObjectIdentifier("2.5.29.74");

        /**
         * delta certificate extension - prototype value will change!
         */
        public static readonly DerObjectIdentifier DRAFT_DeltaCertificateDescriptor =
            new DerObjectIdentifier("2.16.840.1.114027.80.6.1");

        private readonly Dictionary<DerObjectIdentifier, X509Extension> m_extensions =
            new Dictionary<DerObjectIdentifier, X509Extension>();
        private readonly List<DerObjectIdentifier> m_ordering;

        public static X509Extension GetExtension(X509Extensions extensions, DerObjectIdentifier oid) =>
            extensions?.GetExtension(oid);

        public static Asn1Object GetExtensionParsedValue(X509Extensions extensions, DerObjectIdentifier oid) =>
            extensions?.GetExtensionParsedValue(oid);

        public static Asn1OctetString GetExtensionValue(X509Extensions extensions, DerObjectIdentifier oid) =>
            extensions?.GetExtensionValue(oid);

        public static X509Extensions GetInstance(object obj)
        {
            if (obj == null)
                return null;

            if (obj is X509Extensions x509Extensions)
                return x509Extensions;

            if (obj is Asn1Sequence sequence)
                return new X509Extensions(sequence);

            // TODO[api] Rename this class to just Extensions and drop support for this
            if (obj is Asn1TaggedObject taggedObject)
                return GetInstance(Asn1Utilities.CheckContextTagClass(taggedObject).GetBaseObject().ToAsn1Object());

            throw new ArgumentException("unknown object in factory: " + Platform.GetTypeName(obj), nameof(obj));
        }

        public static X509Extensions GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new X509Extensions(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static X509Extensions GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is X509Extensions existing)
                return existing;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new X509Extensions(asn1Sequence);

            return null;
        }

        public static X509Extensions GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new X509Extensions(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        /**
         * Constructor from Asn1Sequence.
         *
         * the extensions are a list of constructed sequences, either with (Oid, OctetString) or (Oid, Boolean, OctetString)
         */
        private X509Extensions(Asn1Sequence seq)
        {
            m_ordering = new List<DerObjectIdentifier>();

            // Don't require empty sequence; we see empty extension blocks in the wild

			foreach (Asn1Encodable ae in seq)
			{
                // TODO Move this block to an X509Extension.GetInstance method

				Asn1Sequence s = Asn1Sequence.GetInstance(ae);

				if (s.Count < 2 || s.Count > 3)
					throw new ArgumentException("Bad sequence size: " + s.Count);

				DerObjectIdentifier oid = DerObjectIdentifier.GetInstance(s[0]);

				bool isCritical = s.Count == 3 && DerBoolean.GetInstance(s[1]).IsTrue;

				Asn1OctetString octets = Asn1OctetString.GetInstance(s[s.Count - 1]);

                if (m_extensions.ContainsKey(oid))
                    throw new ArgumentException("repeated extension found: " + oid);

                m_extensions.Add(oid, new X509Extension(isCritical, octets));
				m_ordering.Add(oid);
			}
        }

        /**
         * constructor from a table of extensions.
         * <p>
         * it's is assumed the table contains Oid/string pairs.</p>
         */
        public X509Extensions(IDictionary<DerObjectIdentifier, X509Extension> extensions)
            : this(null, extensions)
        {
        }

        /**
         * Constructor from a table of extensions with ordering.
         * <p>
         * It's is assumed the table contains Oid/string pairs.</p>
         */
        public X509Extensions(IList<DerObjectIdentifier> ordering,
            IDictionary<DerObjectIdentifier, X509Extension> extensions)
        {
            if (ordering == null)
            {
                m_ordering = new List<DerObjectIdentifier>(extensions.Keys);
            }
            else
            {
                m_ordering = new List<DerObjectIdentifier>(ordering);
            }

            foreach (DerObjectIdentifier oid in m_ordering)
            {
                m_extensions.Add(oid, extensions[oid]);
            }
        }

        /**
         * Constructor from two vectors
         *
         * @param objectIDs an ArrayList of the object identifiers.
         * @param values an ArrayList of the extension values.
         */
        public X509Extensions(IList<DerObjectIdentifier> oids, IList<X509Extension> values)
        {
            m_ordering = new List<DerObjectIdentifier>(oids);

            int count = 0;
            foreach (DerObjectIdentifier oid in m_ordering)
            {
                m_extensions.Add(oid, values[count++]);
            }
        }

        public int Count => m_ordering.Count;

		/**
		 * return an Enumeration of the extension field's object ids.
		 */
		public IEnumerable<DerObjectIdentifier> ExtensionOids
        {
			get { return CollectionUtilities.Proxy(m_ordering); }
        }

		/**
         * return the extension represented by the object identifier
         * passed in.
         *
         * @return the extension if it's present, null otherwise.
         */
        public X509Extension GetExtension(DerObjectIdentifier oid) =>
            CollectionUtilities.GetValueOrNull(m_extensions, oid);

        /**
         * return the parsed value of the extension represented by the object identifier
         * passed in.
         *
         * @return the parsed value of the extension if it's present, null otherwise.
         */
        public Asn1Object GetExtensionParsedValue(DerObjectIdentifier oid) => GetExtension(oid)?.GetParsedValue();

        public Asn1OctetString GetExtensionValue(DerObjectIdentifier oid) => GetExtension(oid)?.Value;

		/**
		 * <pre>
		 *     Extensions        ::=   SEQUENCE SIZE (1..MAX) OF Extension
		 *
		 *     Extension         ::=   SEQUENCE {
		 *        extnId            EXTENSION.&amp;id ({ExtensionSet}),
		 *        critical          BOOLEAN DEFAULT FALSE,
		 *        extnValue         OCTET STRING }
		 * </pre>
		 */
		public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector	v = new Asn1EncodableVector(m_ordering.Count);

			foreach (DerObjectIdentifier oid in m_ordering)
			{
                X509Extension ext = m_extensions[oid];
                if (ext.IsCritical)
                {
                    v.Add(new DerSequence(oid, DerBoolean.True, ext.Value));
                }
                else
                {
                    v.Add(new DerSequence(oid, ext.Value));
                }
            }

			return new DerSequence(v);
        }

        internal Asn1Sequence ToAsn1ObjectTrimmed()
        {
            int count = m_ordering.Count - (m_extensions.ContainsKey(AltSignatureValue) ? 1 : 0);

            Asn1EncodableVector v = new Asn1EncodableVector(count);

            foreach (DerObjectIdentifier oid in m_ordering)
            {
                if (AltSignatureValue.Equals(oid))
                    continue;

                X509Extension ext = m_extensions[oid];
                if (ext.IsCritical)
                {
                    v.Add(new DerSequence(oid, DerBoolean.True, ext.Value));
                }
                else
                {
                    v.Add(new DerSequence(oid, ext.Value));
                }
            }

            return new DerSequence(v);
        }
		public bool Equivalent(X509Extensions other)
		{
			if (m_extensions.Count != other.m_extensions.Count)
				return false;

            foreach (var entry in m_extensions)
            {
                if (!entry.Value.Equals(other.GetExtension(entry.Key)))
                    return false;
            }

			return true;
		}

		public DerObjectIdentifier[] GetExtensionOids() => m_ordering.ToArray();

		public DerObjectIdentifier[] GetNonCriticalExtensionOids() => GetExtensionOids(false);

		public DerObjectIdentifier[] GetCriticalExtensionOids() => GetExtensionOids(true);

        public bool HasAnyCriticalExtensions()
        {
            foreach (DerObjectIdentifier oid in m_ordering)
            {
                if (m_extensions[oid].IsCritical)
                    return true;
            }

            return false;
        }

        private DerObjectIdentifier[] GetExtensionOids(bool isCritical)
		{
			var oids = new List<DerObjectIdentifier>();

			foreach (DerObjectIdentifier oid in m_ordering)
            {
				if (m_extensions[oid].IsCritical == isCritical)
				{
					oids.Add(oid);
				}
            }

            return oids.ToArray();
		}
	}
}
