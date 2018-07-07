using System;
using System.Collections.Generic;
using System.Text;

namespace LoRaLib.LoRaMessagePayload
{

    /// <summary>
    /// The LoRaPayloadWrapper class wraps all the information any LoRa message share in common
    /// </summary>
    public abstract class LoRaGenericPayload
    {
        /// <summary>
        /// raw byte of the message
        /// </summary>
        public byte[] rawMessage;
        /// <summary>
        /// MACHeader of the message
        /// </summary>
        public Memory<byte> mhdr;

        /// <summary>
        /// Message Integrity Code
        /// </summary>
        public Memory<byte> mic;


        /// <summary>
        /// Assigned Dev Address
        /// </summary>
        public byte[] devAddr;


        /// <summary>
        /// Wrapper of a LoRa message, consisting of the MIC and MHDR, common to all LoRa messages
        /// This is used for uplink / decoding
        /// </summary>
        /// <param name="inputMessage"></param>
        public LoRaGenericPayload(byte[] inputMessage)
        {
            rawMessage = inputMessage;
            //get the mhdr
            this.mhdr = inputMessage;
            mhdr.Slice(0, 1);

            //MIC 4 last bytes
            byte[] mic = new byte[4];
            Array.Copy(inputMessage, inputMessage.Length - 4, mic, 0, 4);
            this.mic = mic;
        }

        /// <summary>
        /// This is used for downlink, The field will be computed at message creation
        /// </summary>
        public LoRaGenericPayload()
        {

        }
    }
}
