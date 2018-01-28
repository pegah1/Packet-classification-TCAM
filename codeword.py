import math
import string
from collections import OrderedDict
from operator import itemgetter


remaine0="00000000000000000000000000000000"
remaine1="11111111111111111111111111111111"

network={}

def read_file():
        print "start..."
        fr = open("rules.txt", "rb")
        index = 1
        for line in fr: #read file contains the rules
                c = line[:len(line)].split(',')
                c[0]= c[0].strip()
                c[1]= c[1].strip()
                
                Net=[]
                for i in range(2):
                        slash = c[i].index("/")
                        netmask = c[i][slash + 1:]
                        netmask = int(netmask) + 1
                        netmask = netmask - 1
                        ip = c[i][:slash]
                        ip = (''.join([bin(int(x) + 256)[3:] for x in ip.split('.')])) #convert to binary
                        Net.append([int(ip[:netmask]+remaine0[:32-netmask],2),int(ip[:netmask]+remaine1[:32-netmask],2)])
                network[index] = Net 
                index +=1
        #print network
def match_rule(inp):
        rule = []
        #print inp[0]
        #print inp[1]
        #print "-----------------------"
        for key, value in network.items():
                if ((inp[0] >= value[0][0] and inp[0] <= value[0][1]) and (inp[1] >= value[1][0] and inp[1] <= value[1][1])):
                        #print "\n",key
                        #print value[0]
                        #print value[1]
                        rule.append(key)
        print rule

def input_query():
        flag = 1
        while flag:
                print '\nif you want to exite type "q" in the form of string\n'
                #sourceip, destinationip
                a = input('Pleas enter source IP and destination IP in the form of string:\nexample: "source IP dest IP"\n')
                #print a 
                if a == "q": return
                else:
                        Net=[]
                        a = a.split(" ")
                        for i in range(2):
                                Net.append(int(''.join([bin(int(x) + 256)[3:] for x in a[i].split('.')]),2)) #convert decimal to binary 
                        #print Net
                        match_rule(Net)
                print "---------------------------------------------------------------------"
                
                
            

read_file()
input_query()

