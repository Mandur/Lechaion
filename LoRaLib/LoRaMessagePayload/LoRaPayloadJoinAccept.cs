using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace LoRaLib.LoRaMessagePayload
{
    /// <summary>
    /// Implementation of a LoRa Join-Accept frame
    /// </summary>
    public class LoRaPayloadJoinAccept : LoRaDataPayload
    {
        /// <summary>
        /// Server Nonce aka JoinNonce
        /// </summary>
        public byte[] appNonce;

        /// <summary>
        /// Device home network aka Home_NetId
        /// </summary>
        public byte[] netID;

        /// <summary>
        /// DLSettings
        /// </summary>
        public byte[] dlSettings;

        /// <summary>
        /// RxDelay
        /// </summary>
        public byte[] rxDelay;

        /// <summary>
        /// CFList / Optional
        /// </summary>
        public byte[] cfList;

        /// <summary>
        /// Frame Counter
        /// </summary>
        public byte[] fcnt;

        public LoRaPayloadJoinAccept(string _netId, string appKey, byte[] _devAddr, byte[] _appNonce)
        {
            appNonce = new byte[3];
            netID = new byte[3];
            devAddr = _devAddr;
            dlSettings = new byte[1] { 0 };
            rxDelay = new byte[1] { 0 };
            //set payload Wrapper fields
            mhdr = new byte[] { 32 };
            appNonce = _appNonce;
            netID = StringToByteArray(_netId.Replace("-", ""));
            //default param 869.525 MHz / DR0 (F12, 125 kHz)  

            //TODO delete
            cfList = null;
            // cfList = StringToByteArray("184F84E85684B85E84886684586E8400");
            fcnt = BitConverter.GetBytes(0x01);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(appNonce);
                Array.Reverse(netID);
                Array.Reverse(devAddr);
            }
            var algoinput = mhdr.ToArray().Concat(appNonce).Concat(netID).Concat(devAddr).Concat(dlSettings).Concat(rxDelay).ToArray();
            if (cfList != null)
                algoinput = algoinput.Concat(cfList).ToArray();

            CalculateMic(appKey, algoinput);
            PerformEncryption(appKey);
        }

        private byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        public override string PerformEncryption(string appSkey)
        {
            //return null;
            AesEngine aesEngine = new AesEngine();
            var key = StringToByteArray(appSkey);
            aesEngine.Init(true, new KeyParameter(key));
            byte[] rfu = new byte[1];
            rfu[0] = 0x0;

            byte[] pt;
            if (cfList != null)
                pt = appNonce.Concat(netID).Concat(devAddr).Concat(rfu).Concat(rxDelay).Concat(cfList).Concat(mic.ToArray()).ToArray();
            else
                pt = appNonce.Concat(netID).Concat(devAddr).Concat(rfu).Concat(rxDelay).Concat(mic.ToArray()).ToArray();

            byte[] ct = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

            Aes aes = new AesManaged();
            aes.Key = key;
            aes.IV = new byte[16];
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;

            ICryptoTransform cipher;

            cipher = aes.CreateDecryptor();
            var encryptedPayload = cipher.TransformFinalBlock(pt, 0, pt.Length);
            rawMessage = new byte[encryptedPayload.Length];
            Array.Copy(encryptedPayload, 0, rawMessage, 0, encryptedPayload.Length);
            return Encoding.Default.GetString(encryptedPayload);

        }





        public override byte[] ToMessage()
        {
            List<byte> messageArray = new List<Byte>();
            messageArray.AddRange(mhdr.ToArray());
            messageArray.AddRange(rawMessage);

            return messageArray.ToArray();
        }

        public override bool CheckMic(string nwskey)
        {
            throw new NotImplementedException();
        }


    }
}
