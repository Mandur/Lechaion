using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace LoRaLib.LoRaMessagePayload
{
    /// <summary>
    /// the body of an Uplink (normal) message
    /// </summary>
    public class LoRaPayloadStandardData : LoRaDataPayload
    {

        /// <summary>
        /// Frame control octet
        /// </summary>
        public byte[] fctrl;
        /// <summary>
        /// Frame Counter
        /// </summary>
        public byte[] fcnt;
        /// <summary>
        /// Optional frame
        /// </summary>
        public byte[] fopts;
        /// <summary>
        /// Port field
        /// </summary>
        public byte[] fport;
        /// <summary>
        /// MAC Frame Payload Encryption 
        /// </summary>
        public byte[] frmpayload;


        /// <summary>
        /// get message direction
        /// </summary>
        public int direction;


        /// <param name="inputMessage"></param>
        public LoRaPayloadStandardData(byte[] inputMessage) : base(inputMessage)
        {

            //get direction
            var checkDir = (mhdr.Span[0] >> 5);
            //in this case the payload is not downlink of our type


            direction = (mhdr.Span[0] & (1 << 6 - 1));

            //get the address
            byte[] addrbytes = new byte[4];
            Array.Copy(inputMessage, 1, addrbytes, 0, 4);
            //address correct but inversed
            Array.Reverse(addrbytes);
            this.devAddr = addrbytes;

            //Fctrl Frame Control Octet
            byte[] fctrl = new byte[1];
            Array.Copy(inputMessage, 5, fctrl, 0, 1);
            byte optlength = new byte();
            int foptsSize = (optlength << 4) >> 4;
            this.fctrl = fctrl;

            //Fcnt
            byte[] fcnt = new byte[2];
            Array.Copy(inputMessage, 6, fcnt, 0, 2);
            this.fcnt = fcnt;

            //FOpts
            byte[] fopts = new byte[foptsSize];
            Array.Copy(inputMessage, 8, fopts, 0, foptsSize);
            this.fopts = fopts;

            //Fport can be empty if no commands! 
            byte[] fport = new byte[1];
            Array.Copy(inputMessage, 8 + foptsSize, fport, 0, 1);
            this.fport = fport;

            //frmpayload
            byte[] FRMPayload = new byte[inputMessage.Length - 9 - 4 - foptsSize];
            Array.Copy(inputMessage, 9 + foptsSize, FRMPayload, 0, inputMessage.Length - 9 - 4 - foptsSize);
            this.frmpayload = FRMPayload;

        }

        public LoRaPayloadStandardData(byte[] _mhdr, byte[] _devAddr, byte[] _fctrl, byte[] _fcnt, byte[] _fOpts, byte[] _fPort, byte[] _frmPayload, int _direction) : base()
        {
            mhdr = _mhdr;
            Array.Reverse(_devAddr);
            devAddr = _devAddr;
            fctrl = _fctrl;
            fcnt = _fcnt;
            fopts = _fOpts;
            fport = _fPort;
            frmpayload = _frmPayload;
            if (frmpayload != null)
                Array.Reverse(frmpayload);
            direction = _direction;
        }

        /// <summary>
        /// Method to check if the mic is valid
        /// </summary>
        /// <param name="nwskey">the network security key</param>
        /// <returns></returns>
        public override bool CheckMic(string nwskey)
        {
            IMac mac = MacUtilities.GetMac("AESCMAC");
            KeyParameter key = new KeyParameter(StringToByteArray(nwskey));
            mac.Init(key);
            byte[] block = { 0x49, 0x00, 0x00, 0x00, 0x00, (byte)direction, (byte)(devAddr[3]), (byte)(devAddr[2]), (byte)(devAddr[1]),
                (byte)(devAddr[0]),  fcnt[0] , fcnt[1],0x00, 0x00, 0x00, (byte)(rawMessage.Length-4) };
            var algoinput = block.Concat(rawMessage.Take(rawMessage.Length - 4)).ToArray();
            byte[] result = new byte[16];
            mac.BlockUpdate(algoinput, 0, algoinput.Length);
            result = MacUtilities.DoFinal(mac);
            return mic.ToArray().SequenceEqual(result.Take(4).ToArray());
        }

        public void SetMic(string nwskey)
        {
            rawMessage = this.ToMessage();
            IMac mac = MacUtilities.GetMac("AESCMAC");
            KeyParameter key = new KeyParameter(StringToByteArray(nwskey));
            mac.Init(key);
            byte[] block = { 0x49, 0x00, 0x00, 0x00, 0x00, (byte)direction, (byte)(devAddr[3]), (byte)(devAddr[2]), (byte)(devAddr[1]),
                (byte)(devAddr[0]),  fcnt[0] , fcnt[1],0x00, 0x00, 0x00, (byte)(rawMessage.Length) };
            var algoinput = block.Concat(rawMessage.Take(rawMessage.Length)).ToArray();
            byte[] result = new byte[16];
            mac.BlockUpdate(algoinput, 0, algoinput.Length);
            result = MacUtilities.DoFinal(mac);
            mic = result.Take(4).ToArray();
        }



        /// <summary>
        /// src https://github.com/jieter/python-lora/blob/master/lora/crypto.py
        /// </summary>
        public override string PerformEncryption(string appSkey)
        {
            if (frmpayload != null)
            {
                AesEngine aesEngine = new AesEngine();
                byte[] tmp = StringToByteArray(appSkey);

                aesEngine.Init(true, new KeyParameter(tmp));

                byte[] aBlock = { 0x01, 0x00, 0x00, 0x00, 0x00, (byte)direction, (byte)(devAddr[3]), (byte)(devAddr[2]), (byte)(devAddr[1]),
                (byte)(devAddr[0]),(byte)(fcnt[0]),(byte)(fcnt[1]),  0x00 , 0x00, 0x00, 0x00 };

                byte[] sBlock = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                int size = frmpayload.Length;
                byte[] decrypted = new byte[size];
                byte bufferIndex = 0;
                short ctr = 1;
                int i;
                while (size >= 16)
                {
                    aBlock[15] = (byte)((ctr) & 0xFF);
                    ctr++;
                    aesEngine.ProcessBlock(aBlock, 0, sBlock, 0);
                    for (i = 0; i < 16; i++)
                    {
                        decrypted[bufferIndex + i] = (byte)(frmpayload[bufferIndex + i] ^ sBlock[i]);
                    }
                    size -= 16;
                    bufferIndex += 16;
                }
                if (size > 0)
                {
                    aBlock[15] = (byte)((ctr) & 0xFF);
                    aesEngine.ProcessBlock(aBlock, 0, sBlock, 0);
                    for (i = 0; i < size; i++)
                    {
                        decrypted[bufferIndex + i] = (byte)(frmpayload[bufferIndex + i] ^ sBlock[i]);
                    }
                }
                frmpayload = decrypted;
                return Encoding.Default.GetString(decrypted);
            }
            else
                return null;
        }

        private byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        public override byte[] ToMessage()
        {
            List<byte> messageArray = new List<Byte>();
            messageArray.AddRange(mhdr.ToArray());
            messageArray.AddRange(devAddr.Reverse().ToArray());
            messageArray.AddRange(fctrl);
            messageArray.AddRange(fcnt);
            if (fopts != null)
                messageArray.AddRange(fopts);
            if (fport != null)
                messageArray.AddRange(fport);
            if (frmpayload != null)
                messageArray.AddRange(frmpayload);
            if (!mic.IsEmpty)
                messageArray.AddRange(mic.ToArray());
            return messageArray.ToArray();
        }


    }
}
