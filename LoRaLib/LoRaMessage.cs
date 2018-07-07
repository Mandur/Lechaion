using LoRaLib.LoRaMessagePayload;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace LoRaLib
{


   
    #region LoRaMessage
    public enum LoRaMessageType
    {
        JoinRequest,
        JoinAccept,
        UnconfirmedDataUp,
        UnconfirmedDataDown,
        ConfirmedDataUp,
        ConfirmedDataDown,
        RFU,
        Proprietary
    }
    /// <summary>
    /// class exposing usefull message stuff
    /// </summary>
    public class LoRaMessage
    {
        /// <summary>
        /// see 
        /// </summary>
        public bool isLoRaMessage = false;
        public LoRaGenericPayload payloadMessage;
        public LoRaMetada loraMetadata;
        public PhysicalPayload physicalPayload;

        /// <summary>
        /// The Message type
        /// </summary>
        public LoRaMessageType loRaMessageType;

        /// <summary>
        /// This contructor is used in case of uplink message, hence we don't know the message type yet
        /// </summary>
        /// <param name="inputMessage"></param>
        public LoRaMessage(byte[] inputMessage)
        {
            //packet normally sent by the gateway as heartbeat. TODO find more elegant way to integrate.

            physicalPayload = new PhysicalPayload(inputMessage);
            if (physicalPayload.message != null)
            {
                loraMetadata = new LoRaMetada(physicalPayload.message);
                //set up the parts of the raw message   
                //status message
                if (loraMetadata.rawB64data != null)
                {
                    byte[] convertedInputMessage = Convert.FromBase64String(loraMetadata.rawB64data);
                    var messageType = convertedInputMessage[0] >> 5;
                    loRaMessageType = (LoRaMessageType)messageType;
                    //Uplink Message
                    if (messageType == (int)LoRaMessageType.UnconfirmedDataUp)
                        payloadMessage = new LoRaPayloadStandardData(convertedInputMessage);
                    else if (messageType == (int)LoRaMessageType.ConfirmedDataUp)
                        payloadMessage = new LoRaPayloadStandardData(convertedInputMessage);
                    else if (messageType == (int)LoRaMessageType.JoinRequest)
                        payloadMessage = new LoRaPayloadJoinRequest(convertedInputMessage);
                    isLoRaMessage = true;
                }
                else
                {

                    isLoRaMessage = false;
                }
            }
            else
            {
                isLoRaMessage = false;
            }

        }

        /// <summary>
        /// This contructor is used in case of downlink message
        /// </summary>
        /// <param name="inputMessage"></param>
        /// <param name="type">
        /// 0 = Join Request
        /// 1 = Join Accept
        /// 2 = Unconfirmed Data up
        /// 3 = Unconfirmed Data down
        /// 4 = Confirmed Data up
        /// 5 = Confirmed Data down
        /// 6 = Rejoin Request</param>
        public LoRaMessage(LoRaGenericPayload payload, LoRaMessageType type, byte[] physicalToken)
        {
            //construct a Join Accept Message
            if (type == LoRaMessageType.JoinAccept)
            {
                payloadMessage = (LoRaPayloadJoinAccept)payload;
                loraMetadata = new LoRaMetada(payloadMessage, type);
                var downlinkmsg = new DownlinkPktFwdMessage(loraMetadata.rawB64data);
                var jsonMsg = JsonConvert.SerializeObject(downlinkmsg);
                var messageBytes = Encoding.Default.GetBytes(jsonMsg);

                physicalPayload = new PhysicalPayload(physicalToken, PhysicalIdentifier.PULL_RESP, messageBytes);


            }
            else if (type == LoRaMessageType.UnconfirmedDataDown)
            {
                throw new NotImplementedException();
            }
            else if (type == LoRaMessageType.ConfirmedDataDown)
            {
                throw new NotImplementedException();
            }

        }

        public LoRaMessage(LoRaGenericPayload payload, LoRaMessageType type, byte[] physicalToken, string _datr, uint _rfch, double _freq, long _tmst)
        {
            //construct a Join Accept Message
            if (type == LoRaMessageType.JoinAccept)
            {
                payloadMessage = (LoRaPayloadJoinAccept)payload;
                loraMetadata = new LoRaMetada(payloadMessage, type);
                var downlinkmsg = new DownlinkPktFwdMessage(loraMetadata.rawB64data, _datr, _rfch, _freq, _tmst + 5000000);

                var jsonMsg = JsonConvert.SerializeObject(downlinkmsg);
                Console.WriteLine(jsonMsg);
                var messageBytes = Encoding.Default.GetBytes(jsonMsg);

                physicalPayload = new PhysicalPayload(physicalToken, PhysicalIdentifier.PULL_RESP, messageBytes);


            }
            else if (type == LoRaMessageType.UnconfirmedDataDown)
            {
                payloadMessage = (LoRaPayloadStandardData)payload;
                loraMetadata = new LoRaMetada(payloadMessage, type);
                var downlinkmsg = new DownlinkPktFwdMessage(loraMetadata.rawB64data, _datr, _rfch, _freq, _tmst + 1000000);

                var jsonMsg = JsonConvert.SerializeObject(downlinkmsg);
                Console.WriteLine(jsonMsg);
                var messageBytes = Encoding.Default.GetBytes(jsonMsg);

                physicalPayload = new PhysicalPayload(physicalToken, PhysicalIdentifier.PULL_RESP, messageBytes);
            }
            else if (type == LoRaMessageType.ConfirmedDataDown)
            {
                payloadMessage = (LoRaPayloadStandardData)payload;
                loraMetadata = new LoRaMetada(payloadMessage, type);
                var downlinkmsg = new DownlinkPktFwdMessage(loraMetadata.rawB64data, _datr, _rfch, _freq, _tmst + 1000000);

                var jsonMsg = JsonConvert.SerializeObject(downlinkmsg);
                Console.WriteLine(jsonMsg);
                var messageBytes = Encoding.Default.GetBytes(jsonMsg);

                physicalPayload = new PhysicalPayload(physicalToken, PhysicalIdentifier.PULL_RESP, messageBytes);
            }

        }

        /// <summary>
        /// Method to map the Mic check to the appropriate implementation.
        /// </summary>
        /// <param name="nwskey">The Neetwork Secret Key</param>
        /// <returns>a boolean telling if the MIC is valid or not</returns>
        public bool CheckMic(string nwskey)
        {
            return ((LoRaDataPayload)payloadMessage).CheckMic(nwskey);
        }

        /// <summary>
        /// Method to decrypt payload to the appropriate implementation.
        /// </summary>
        /// <param name="nwskey">The Application Secret Key</param>
        /// <returns>a boolean telling if the MIC is valid or not</returns>
        public string DecryptPayload(string appSkey)
        {
            var retValue = ((LoRaDataPayload)payloadMessage).PerformEncryption(appSkey);
            loraMetadata.decodedData = retValue;
            return retValue;
        }
    }
    #endregion
    #region LoRaMetada

    /// <summary>
    /// Metadata about a Lora Packet, featuring a Lora Packet, the payload and the data.
    /// </summary>
    public class LoRaMetada
    {

        public PktFwdMessage fullPayload { get; set; }
        public string rawB64data { get; set; }
        public string decodedData { get; set; }



        /// <summary>
        /// Case of Uplink message. 
        /// </summary>
        /// <param name="input"></param>
        public LoRaMetada(byte[] input)
        {
            var payload = Encoding.Default.GetString(input);
            Console.WriteLine(payload);
            var payloadObject = JsonConvert.DeserializeObject<UplinkPktFwdMessage>(payload);
            fullPayload = payloadObject;
            //TODO to this in a loop.
            if (payloadObject.rxpk.Count > 0)
            {
                rawB64data = payloadObject.rxpk[0].data;
            }

        }

        /// <summary>
        /// Case of Downlink message. TODO refactor this
        /// </summary>
        /// <param name="input"></param>
        public LoRaMetada(LoRaGenericPayload payloadMessage, LoRaMessageType messageType)
        {
            if (messageType == LoRaMessageType.JoinAccept)
                rawB64data = Convert.ToBase64String(((LoRaPayloadJoinAccept)payloadMessage).ToMessage());
            else if (messageType == LoRaMessageType.UnconfirmedDataDown || messageType == LoRaMessageType.ConfirmedDataDown)
                rawB64data = Convert.ToBase64String(((LoRaPayloadStandardData)payloadMessage).ToMessage());


        }
    }
    #endregion



}
