#! /usr/bin/env python3

from collections import Counter
from scapy.all import sniff
from subprocess import call 
import os, time
from terminaltables import SingleTable
import fire


packet_counts = Counter()



def clear(): 
    _ = call('clear' if os.name =='posix' else 'cls') 


def sniffer(filter='ip'):
	global FILTER
	FILTER = filter
	def custom_action(packet):
		
		saida=[['Addres','Ocorrencies']]
		key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
		packet_counts.update([key])	
		teste=sorted(packet_counts.items(), key=lambda k: -k[1])
		int=0
		for line in teste:
			if line[1] > 10 and int < 30:

				saida.append([line[0][0]+" -> "+line[0][1],line[1]])
				int=int+1	
		clear()
		return SingleTable(saida).table

	sniff(filter=FILTER, prn=custom_action, count=-1)



if __name__ == '__main__':
  fire.Fire(sniffer)