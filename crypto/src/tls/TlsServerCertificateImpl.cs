using System;

namespace Org.BouncyCastle.Tls
{
    internal sealed class TlsServerCertificateImpl
        : TlsServerCertificate
    {
        private readonly Certificate m_certificate;
        private readonly CertificateStatus m_certificateStatus;
        private readonly CertificateStatus[] m_certificateStatuses;

        /// <param name="certificate">
        /// The Server Certificate message.
        /// </param>
        /// <param name="certificateStatus">
        /// What <see cref="CertificateStatus"/> answers with: up to TLS 1.2 the "certificate_status" message as it
        /// arrived, which is the ocsp_multi list itself where the client asked with "status_request_v2"; from TLS 1.3
        /// the first entry's staple.
        /// </param>
        /// <param name="certificateStatuses">
        /// One entry per certificate of <paramref name="certificate"/>, null where that certificate was left unstapled.
        /// </param>
        internal TlsServerCertificateImpl(Certificate certificate, CertificateStatus certificateStatus,
            CertificateStatus[] certificateStatuses)
        {
            m_certificate = certificate;
            m_certificateStatus = certificateStatus;
            m_certificateStatuses = certificateStatuses;
        }

        public Certificate Certificate => m_certificate;

        public CertificateStatus CertificateStatus => m_certificateStatus;

        public CertificateStatus GetCertificateStatusAt(int index)
        {
            if (index < 0 || index >= m_certificateStatuses.Length)
                return null;

            return m_certificateStatuses[index];
        }
    }
}
