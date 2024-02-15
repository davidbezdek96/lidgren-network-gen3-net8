using System;
using System.IO;
using System.Security.Cryptography;

namespace Lidgren.Network
{
	public abstract class NetCryptoProviderBase : NetEncryption
	{
		protected SymmetricAlgorithm m_algorithm;

		public NetCryptoProviderBase(NetPeer peer, SymmetricAlgorithm algo)
			: base(peer)
		{
			m_algorithm = algo;
			m_algorithm.GenerateKey();
			m_algorithm.GenerateIV();
		}

		public override void SetKey(byte[] data, int offset, int count)
		{
			int len = m_algorithm.Key.Length;
			var key = new byte[len];
			for (int i = 0; i < len; i++)
				key[i] = data[offset + (i % count)];
			m_algorithm.Key = key;

			len = m_algorithm.IV.Length;
			key = new byte[len];
			for (int i = 0; i < len; i++)
				key[len - 1 - i] = data[offset + (i % count)];
			m_algorithm.IV = key;
		}

        public override bool Encrypt(NetOutgoingMessage msg)
        {
            var plainBytes = msg.Data;
            int unEncLenBits = msg.LengthBits;
            byte[] encryptedBytes;

            // Encrypt the data
            using (var ms = new MemoryStream())
            {
                using (var cs = new CryptoStream(ms, m_algorithm.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(plainBytes, 0, msg.LengthBytes);
                    cs.FlushFinalBlock();
                }

                encryptedBytes = ms.ToArray();
            }

            // Assuming you want to rewrite the msg with encrypted data and its original length
            int arrLength = (encryptedBytes.Length + 4) * 8; // Adjusted for actual encrypted length
            msg.EnsureBufferSize(arrLength);
            msg.LengthBits = 0; // Reset write pointer
            msg.Write((uint)unEncLenBits); // Write original message length
            msg.Write(encryptedBytes); // Write encrypted data
            msg.LengthBits = arrLength; // Adjust length bits to match new content

            return true;
        }


        //public override bool Encrypt(NetOutgoingMessage msg)
        //{
        //	var plainBytes = msg.Data;

        //	int unEncLenBits = msg.LengthBits;

        //	byte[] encryptedBytes;

        //	using (var ms = new MemoryStream())
        //	{
        //		using (var cs = new CryptoStream(ms, m_algorithm.CreateEncryptor(), CryptoStreamMode.Write))
        //		{
        //			cs.Write(plainBytes, 0, msg.LengthBytes);
        //			cs.FlushFinalBlock();
        //			cs.Close();
        //		}

        //		encryptedBytes = ms.ToArray();
        //		ms.Close();
        //          }

        //	var arrLength = (encryptedBytes.Length + 4) * 8;

        //	var decBuffer = new byte[msg.LengthBytes];
        //	using (var decMs = new MemoryStream(encryptedBytes, 0, encryptedBytes.Length))
        //	using (var decCs = new CryptoStream(decMs, m_algorithm.CreateDecryptor(), CryptoStreamMode.Read))
        //	{
        //		int read = 0;
        //		var rem = msg.LengthBytes;

        //              do
        //              {
        //                  read = decCs.Read(decBuffer, read, rem);
        //                  rem -= read;
        //              }
        //              while (read > 0);
        //	}

        //	// get results

        //	var msgData = string.Join(',', plainBytes);
        //	var EncryptedData = string.Join(',', decBuffer);

        //	msg.EnsureBufferSize(arrLength);
        //	msg.LengthBits = 0; // reset write pointer
        //	msg.Write((uint)unEncLenBits);
        //	msg.Write(encryptedBytes);
        //	msg.LengthBits = arrLength;

        //	return true;
        //}

        public override bool Decrypt(NetIncomingMessage msg)
        {
            // Read the length of the unencrypted data in bits and calculate the byte length needed
            int unEncLenBits = (int)msg.ReadUInt32();
            var byteLen = NetUtility.BytesToHoldBits(unEncLenBits);

            // Prepare a buffer for the decrypted data
            var decryptedData = new byte[byteLen]; // Adjusted to use a local buffer instead of from pool for clarity

            // Initialize MemoryStream with the offset and length for the actual encrypted data in msg
            using (var ms = new MemoryStream(msg.m_data, 4, msg.LengthBytes - 4))
            {
                using (var cs = new CryptoStream(ms, m_algorithm.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    int totalRead = 0; // Use totalRead to track the total bytes decrypted
                    int currentRead;

                    // Read from the CryptoStream until all data is decrypted
                    while ((currentRead = cs.Read(decryptedData, totalRead, decryptedData.Length - totalRead)) > 0)
                    {
                        totalRead += currentRead;
                    }
                    // No need to manually close CryptoStream or MemoryStream as using block takes care of it
                }
            }

            // Assuming recycling or reusing msg is handled elsewhere as indicated by the TODO

            // Update the msg with decrypted data
            msg.m_data = decryptedData;
            msg.m_bitLength = unEncLenBits; // Set the bit length to the original unencrypted message length
            msg.m_readPosition = 0; // Reset read position for further reading

            return true;
        }

  //      public override bool Decrypt(NetIncomingMessage msg)
		//{
		//	int unEncLenBits = (int)msg.ReadUInt32();
		//	var byteLen = NetUtility.BytesToHoldBits(unEncLenBits);
		//	var decryptedData = m_peer.GetStorage(byteLen);

		//	using (var ms = new MemoryStream(msg.m_data, 4, msg.LengthBytes - 4))
		//	{
		//		using (var cs = new CryptoStream(ms, m_algorithm.CreateDecryptor(), CryptoStreamMode.Read))
		//		{
  //                  int read = 0;
  //                  var rem = byteLen;

  //                  do
  //                  {
  //                      read = cs.Read(decryptedData, read, rem);
  //                      rem -= read;
  //                  }
  //                  while (read > 0);

		//			cs.Close();
  //              }
		//	}

		//	// TODO: recycle existing msg

		//	msg.m_data = decryptedData;
		//	msg.m_bitLength = unEncLenBits;
		//	msg.m_readPosition = 0;

		//	return true;
		//}
	}
}
