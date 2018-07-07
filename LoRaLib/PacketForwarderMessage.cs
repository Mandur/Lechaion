using System;
using System.Collections.Generic;
using System.Text;

namespace LoRaLib
{

    /// <summary>
    /// Base type of a Packet Forwarder message (lower level)
    /// </summary>
    public class PktFwdMessage
    {
        PktFwdType pktFwdType;
    }


    enum PktFwdType
    {
        Downlink,
        Uplink
    }

    /// <summary>
    /// JSON of a Downlink message for the Packet forwarder.
    /// </summary>
    public class DownlinkPktFwdMessage : PktFwdMessage
    {
        public Txpk txpk;


        //TODO change values to match network
        public DownlinkPktFwdMessage(string _data)
        {
            var byteData = Convert.FromBase64String(_data);
            txpk = new Txpk()
            {
                imme = true,
                data = _data,
                size = (uint)byteData.Length,
                freq = 869.525000,
                rfch = 0,
                modu = "LORA",
                datr = "SF12BW125",
                codr = "4/5",
                powe = 14

            };
        }

        public DownlinkPktFwdMessage(string _data, string _datr, uint _rfch, double _freq, long _tmst)
        {
            var byteData = Convert.FromBase64String(_data);
            txpk = new Txpk()
            {
                imme = false,
                tmst = _tmst,
                data = _data,
                size = (uint)byteData.Length,
                freq = _freq,
                rfch = _rfch,
                modu = "LORA",
                datr = _datr,
                codr = "4/5",
                powe = 14,
                ipol = true

            };
        }
    }


    /// <summary>
    /// an uplink Json for the packet forwarder.
    /// </summary>
    public class UplinkPktFwdMessage : PktFwdMessage
    {
        public List<Rxpk> rxpk = new List<Rxpk>();
    }

}
