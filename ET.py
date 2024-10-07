from scapy.all import *
from scapy.layers.inet import *
import termcolor
import hashlib
import datetime


def process_packet(pkt):
    """
    Callback function to decode data from the captured packet,
    and send a message when all required parameters are collected
    :param pkt: the packet
    :return: none
    """
    # global variables that need to be retained across function calls
    global loc_data
    global airport_code
    global travel_lane
    global travel_vehicle

    # print and decode the data
    packet_data = pkt[Raw].load.decode()
    caesar_shift = int(packet_data[3:6])
    decoded_message = caesar_cipher(packet_data, caesar_shift)
    if pkt[IP].dst == "54.71.128.194":
        termcolor.cprint(decoded_message, "grey", "on_red")
    else:
        termcolor.cprint(decoded_message, "grey", "on_cyan")

    # receive the parameters for the FLY message
    if "/10" in decoded_message:
        loc_data += decoded_message[decoded_message.find(":")+2:]
    elif "airport selected for takeoff" in decoded_message:
        airport_code = decoded_message[decoded_message.find(":")+2:]
    elif "determining chosen lane for travel" in decoded_message:
        travel_lane = decoded_message[decoded_message.find(":")+2:]
    elif "vehicle chosed for travel" in decoded_message:
        travel_vehicle = decoded_message[decoded_message.find("id")+3:]

    # check if all required parameters are collected
    if "10/10" in decoded_message:
        # fix the time issue
        current_time = datetime.datetime.now().strftime("%H:%M")

        raw_message = f"FLY008location_md5={hashlib.md5(loc_data.encode()).hexdigest()},airport={airport_code},time={current_time},lane={travel_lane},vehicle={travel_vehicle},fly"
        final_message = Ether() / IP(dst=pkt[IP].src, src=pkt[IP].dst) / UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / Raw(load=caesar_cipher(raw_message, -8))
        srp1(final_message, verbose=0)
        loc_data = ""


def caesar_cipher(text, shift):
    """
    Function to encode/decode a string using Caesar cipher on even indices
    :param text: the string to encode/decode
    :param shift: the Caesar cipher shift value
    :return: the encoded/decoded message
    """
    encoded_text = ""
    for index in range(len(text)):
        if index % 2 != 0:
            encoded_text += text[index]
        elif text[index].islower():
            encoded_text += chr(((ord(text[index]) - shift - 97) % 26) + 97)
        else:
            encoded_text += text[index]
    return encoded_text


def alien_filter(packet):
    """
    Packet filter to check if one of the addresses in the packet is from the alien server
    :param packet: the packet
    :return: True if the packet is from the alien server, False otherwise
    """
    return IP in packet and (packet[IP].dst == "54.71.128.194" or packet[IP].src == "54.71.128.194")


def main():
    sniff(lfilter=alien_filter, prn=process_packet)


if __name__ == "__main__":
    main()