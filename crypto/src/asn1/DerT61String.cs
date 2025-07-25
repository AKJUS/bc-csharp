using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    /**
     * Der T61String (also the teletex string) - 8-bit characters
     */
    public class DerT61String
        : DerStringBase
    {
        internal class Meta : Asn1UniversalType
        {
            internal static readonly Asn1UniversalType Instance = new Meta();

            private Meta() : base(typeof(DerT61String), Asn1Tags.T61String) {}

            internal override Asn1Object FromImplicitPrimitive(DerOctetString octetString)
            {
                return CreatePrimitive(octetString.GetOctets());
            }
        }

		/**
         * return a T61 string from the passed in object.
         *
         * @exception ArgumentException if the object cannot be converted.
         */
        public static DerT61String GetInstance(object obj)
        {
            if (obj == null)
                return null;

            if (obj is DerT61String derT61String)
                return derT61String;

            if (obj is IAsn1Convertible asn1Convertible)
            {
                if (!(obj is Asn1Object) && asn1Convertible.ToAsn1Object() is DerT61String converted)
                    return converted;
            }
            else if (obj is byte[] bytes)
            {
                try
                {
                    return (DerT61String)Meta.Instance.FromByteArray(bytes);
                }
                catch (IOException e)
                {
                    throw new ArgumentException("failed to construct T61 string from byte[]: " + e.Message);
                }
            }

            throw new ArgumentException("illegal object in GetInstance: " + Platform.GetTypeName(obj));
        }

        /**
         * return a T61 string from a tagged object.
         *
         * @param taggedObject the tagged object holding the object we want
         * @param declaredExplicit true if the object is meant to be explicitly tagged false otherwise.
         * @exception ArgumentException if the tagged object cannot be converted.
         */
        public static DerT61String GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return (DerT61String)Meta.Instance.GetContextTagged(taggedObject, declaredExplicit);
        }

        public static DerT61String GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is DerT61String existing)
                return existing;

            return null;
        }

        public static DerT61String GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return (DerT61String)Meta.Instance.GetTagged(taggedObject, declaredExplicit);
        }

        private readonly byte[] m_contents;

        public DerT61String(string str)
        {
			if (str == null)
				throw new ArgumentNullException("str");

            m_contents = Strings.ToByteArray(str);
        }

        public DerT61String(byte[] contents)
            : this(contents, true)
        {
        }

        internal DerT61String(byte[] contents, bool clone)
        {
            if (null == contents)
                throw new ArgumentNullException("contents");

            m_contents = clone ? Arrays.Clone(contents) : contents;
        }

        public override string GetString()
        {
            return Strings.FromByteArray(m_contents);
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            return new PrimitiveEncoding(Asn1Tags.Universal, Asn1Tags.T61String, m_contents);
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            return new PrimitiveEncoding(tagClass, tagNo, m_contents);
        }

        internal sealed override DerEncoding GetEncodingDer()
        {
            return new PrimitiveDerEncoding(Asn1Tags.Universal, Asn1Tags.T61String, m_contents);
        }

        internal sealed override DerEncoding GetEncodingDerImplicit(int tagClass, int tagNo)
        {
            return new PrimitiveDerEncoding(tagClass, tagNo, m_contents);
        }

        public byte[] GetOctets()
        {
            return Arrays.Clone(m_contents);
        }

        protected override bool Asn1Equals(Asn1Object asn1Object)
        {
            DerT61String that = asn1Object as DerT61String;
            return null != that
                && Arrays.AreEqual(this.m_contents, that.m_contents);
        }

        protected override int Asn1GetHashCode()
        {
            return Arrays.GetHashCode(m_contents);
        }

        internal static DerT61String CreatePrimitive(byte[] contents)
        {
            return new DerT61String(contents, false);
        }
    }
}
