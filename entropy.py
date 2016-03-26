from netzob.all import *
import sys
import binascii
from netzob.Inference.Vocabulary.EntropyMeasurement import EntropyMeasurement

path_to_pcap = sys.argv[1]


print 'Loading the pcap...'
messages = PCAPImporter.readFile(path_to_pcap).values()
while True:
    source_or_destination = raw_input("Enter the source: ")
    length_of_payload = raw_input("Enter the length of payload: ")

    print 'Filtering by source..'

    # Filter packets where source or destination is given source address
    messages_filtered_by_source = [message for message in messages if source_or_destination \
                                      in message.source or source_or_destination in message.destination]

    print 'Filtering by length..'

    messages_filtered_by_length = [d.data.encode("HEX") for d in messages_filtered_by_source]

    messages_filtered_by_length = [message for message in messages_filtered_by_length if len(message)/2==int(length_of_payload)]
 
    print 'Finding entropy across %s packets ..' %(len(messages_filtered_by_length))

    messages_raw = [RawMessage(binascii.unhexlify(val)) for val in messages_filtered_by_length]
    try:
        entropy_list = [byte_entropy for byte_entropy in EntropyMeasurement.measure_entropy(messages_raw)]
    except:
        print 'Not many packets found.'
        continue
    print entropy_list

