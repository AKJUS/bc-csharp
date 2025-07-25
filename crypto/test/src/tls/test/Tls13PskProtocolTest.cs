﻿using System;
using System.IO;
using System.Threading;

using NUnit.Framework;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Tls.Tests
{
    [TestFixture]
    public class Tls13PskProtocolTest
    {
        [Test]
        public void BadClientKey()
        {
            MockPskTls13Client client = new MockPskTls13Client(badKey: true);
            MockPskTls13Server server = new MockPskTls13Server();

            ImplTestKeyMismatch(client, server);
        }

        [Test]
        public void BadServerKey()
        {
            MockPskTls13Client client = new MockPskTls13Client();
            MockPskTls13Server server = new MockPskTls13Server(badKey: true);

            ImplTestKeyMismatch(client, server);
        }

        [Test]
        public void TestClientServer()
        {
            MockPskTls13Client client = new MockPskTls13Client();
            MockPskTls13Server server = new MockPskTls13Server();

            PipedStream clientPipe = new PipedStream();
            PipedStream serverPipe = new PipedStream(clientPipe);

            TlsClientProtocol clientProtocol = new TlsClientProtocol(clientPipe);
            TlsServerProtocol serverProtocol = new TlsServerProtocol(serverPipe);

            ServerTask serverTask = new ServerTask(serverProtocol, server);
            Thread serverThread = new Thread(serverTask.Run);
            serverThread.Start();

            clientProtocol.Connect(client);

            byte[] data = new byte[1000];
            client.Crypto.SecureRandom.NextBytes(data);

            Stream output = clientProtocol.Stream;
            output.Write(data, 0, data.Length);

            byte[] echo = new byte[data.Length];
            int count = Streams.ReadFully(clientProtocol.Stream, echo);

            Assert.AreEqual(count, data.Length);
            Assert.IsTrue(Arrays.AreEqual(data, echo));

            output.Close();

            serverThread.Join();
        }

        private void ImplTestKeyMismatch(MockPskTls13Client client, MockPskTls13Server server)
        {
            PipedStream clientPipe = new PipedStream();
            PipedStream serverPipe = new PipedStream(clientPipe);

            TlsClientProtocol clientProtocol = new TlsClientProtocol(clientPipe);
            TlsServerProtocol serverProtocol = new TlsServerProtocol(serverPipe);

            ServerTask serverTask = new ServerTask(serverProtocol, server);
            Thread serverThread = new Thread(serverTask.Run);
            serverThread.Start();

            bool correctException = false;
            short alertDescription = -1;

            try
            {
                clientProtocol.Connect(client);
            }
            catch (TlsFatalAlertReceived e)
            {
                correctException = true;
                alertDescription = e.AlertDescription;
            }
            catch (Exception)
            {
            }
            finally
            {
                clientProtocol.Close();
            }

            serverThread.Join();

            Assert.True(correctException);
            Assert.AreEqual(AlertDescription.decrypt_error, alertDescription);
        }

        internal class ServerTask
        {
            private readonly TlsServerProtocol m_serverProtocol;
            private readonly TlsServer m_server;

            internal ServerTask(TlsServerProtocol serverProtocol, TlsServer server)
            {
                this.m_serverProtocol = serverProtocol;
                this.m_server = server;
            }

            public void Run()
            {
                try
                {
                    m_serverProtocol.Accept(m_server);
                    Streams.PipeAll(m_serverProtocol.Stream, m_serverProtocol.Stream);
                    m_serverProtocol.Close();
                }
                catch (Exception)
                {
                }
            }
        }
    }
}
