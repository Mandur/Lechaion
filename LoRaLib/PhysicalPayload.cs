﻿using System;
using System.Collections.Generic;
using System.Text;

namespace LoRaLib
{
    public enum PhysicalIdentifier
    {
        PUSH_DATA, PUSH_ACK, PULL_DATA, PULL_RESP, PULL_ACK, TX_ACK
    }

    /// <summary>
    /// The Physical Payload wrapper
    /// </summary>
    public class PhysicalPayload
    {

        //case of inbound messages
        public PhysicalPayload(byte[] input)
        {

            protocolVersion = input[0];
            Array.Copy(input, 1, token, 0, 2);
            identifier = (PhysicalIdentifier)input[3];

            //PUSH_DATA That packet type is used by the gateway mainly to forward the RF packets received, and associated metadata, to the server
            if (identifier == PhysicalIdentifier.PUSH_DATA)
            {
                Array.Copy(input, 4, gatewayIdentifier, 0, 8);
                message = new byte[input.Length - 12];
                Array.Copy(input, 12, message, 0, input.Length - 12);
            }

            //PULL_DATA That packet type is used by the gateway to poll data from the server.
            if (identifier == PhysicalIdentifier.PULL_DATA)
            {
                Array.Copy(input, 4, gatewayIdentifier, 0, 8);
            }

            //TX_ACK That packet type is used by the gateway to send a feedback to the to inform if a downlink request has been accepted or rejected by the gateway.
            if (identifier == PhysicalIdentifier.TX_ACK)
            {
                Console.WriteLine("TX ACK RECEIVED");
                Array.Copy(input, 4, gatewayIdentifier, 0, 8);
                if (input.Length - 12 > 0)
                {
                    message = new byte[input.Length - 12];
                    Array.Copy(input, 12, message, 0, input.Length - 12);
                }
            }
        }

        //downlink transmission
        public PhysicalPayload(byte[] _token, PhysicalIdentifier type, byte[] _message)
        {
            //0x01 PUSH_ACK That packet type is used by the server to acknowledge immediately all the PUSH_DATA packets received.
            //0x04 PULL_ACK That packet type is used by the server to confirm that the network route is open and that the server can send PULL_RESP packets at any time.
            if (type == PhysicalIdentifier.PUSH_ACK || type == PhysicalIdentifier.PULL_ACK)
            {
                token = _token;
                identifier = type;
            }

            //0x03 PULL_RESP That packet type is used by the server to send RF packets and  metadata that will have to be emitted by the gateway.
            if (type == PhysicalIdentifier.PULL_RESP)
            {
                token = _token;
                identifier = type;
                message = new byte[_message.Length];
                Array.Copy(_message, 0, message, 0, _message.Length);

            }

        }

        //1 byte
        public byte protocolVersion = 2;
        //1-2 bytes
        public byte[] token = new byte[2];
        //1 byte
        public PhysicalIdentifier identifier;
        //8 bytes
        public byte[] gatewayIdentifier = new byte[8];
        //0-unlimited
        public byte[] message;

        public byte[] GetMessage()
        {
            List<byte> returnList = new List<byte>();
            returnList.Add(protocolVersion);
            returnList.AddRange(token);
            returnList.Add((byte)identifier);
            if (identifier == PhysicalIdentifier.PULL_DATA ||
                identifier == PhysicalIdentifier.TX_ACK ||
                identifier == PhysicalIdentifier.PUSH_DATA
                )
                returnList.AddRange(gatewayIdentifier);
            if (message != null)
                returnList.AddRange(message);
            return returnList.ToArray();
        }
    }
    public class Txpk
    {
        public bool imme;
        public string data;
        public long tmst;
        public uint size;
        public double freq; //868
        public uint rfch;
        public string modu;
        public string datr;
        public string codr;
        public uint powe;
        public bool ipol;
    }

    public class Rxpk
    {
        public string time;
        public uint tmms;
        public uint tmst;
        public double freq; //868
        public uint chan;
        public uint rfch;
        public int stat;
        public string modu;
        public string datr;
        public string codr;
        public int rssi;
        public float lsnr;
        public uint size;
        public string data;
    }
}
