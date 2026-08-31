using System;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Exception thrown by a stateful signature algorithm when the private key counter is exhausted.
    /// </summary>
    [Serializable]
    public class ExhaustedPrivateKeyException
        : InvalidOperationException
    {
        public ExhaustedPrivateKeyException()
            : base()
        {
        }

        public ExhaustedPrivateKeyException(string message)
            : base(message)
        {
        }

        public ExhaustedPrivateKeyException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        protected ExhaustedPrivateKeyException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
