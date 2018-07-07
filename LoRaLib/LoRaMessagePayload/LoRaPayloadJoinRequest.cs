using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace LoRaLib.LoRaMessagePayload
{
    /// <summary>
    /// Implementation of the Join Request message type.
    /// </summary>
    public class LoRaPayloadJoinRequest : LoRaDataPayload
    {

        //aka JoinEUI
        public byte[] appEUI;
        public byte[] devEUI;
        public byte[] devNonce;

        public LoRaPayloadJoinRequest(byte[] inputMessage) : base(inputMessage)
        {

            var inputmsgstr = BitConverter.ToString(inputMessage);
            //get the joinEUI field
            appEUI = new byte[8];
            Array.Copy(inputMessage, 1, appEUI, 0, 8);

            var appEUIStr = BitConverter.ToString(appEUI);
            //get the DevEUI
            devEUI = new byte[8];
            Array.Copy(inputMessage, 9, devEUI, 0, 8);

            var devEUIStr = BitConverter.ToString(devEUI);
            //get the DevNonce
            devNonce = new byte[2];
            Array.Copy(inputMessage, 17, devNonce, 0, 2);

            var devNonceStr = BitConverter.ToString(devNonce);

        }



        public override bool CheckMic(string AppKey)
        {
            //appEUI = StringToByteArray("526973696E674846");
            IMac mac = MacUtilities.GetMac("AESCMAC");

            KeyParameter key = new KeyParameter(StringToByteArray(AppKey));
            mac.Init(key);

            byte[] tmp = new byte[0];
            var algoinput = tmp.Concat(mhdr.ToArray()).Concat(appEUI).Concat(devEUI).Concat(devNonce).ToArray();
            byte[] result = new byte[19];
            mac.BlockUpdate(algoinput, 0, algoinput.Length);
            result = MacUtilities.DoFinal(mac);
            var resStr = BitConverter.ToString(result);
            return mic.ToArray().SequenceEqual(result.Take(4).ToArray());
        }

        public override string PerformEncryption(string appSkey)
        {
            throw new NotImplementedException("The payload is not encrypted in case of a join message");
        }

        public override byte[] ToMessage()
        {
            throw new NotImplementedException();
        }

        private byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }
    }
}
