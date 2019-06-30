#!/usr/bin/python3

# jmathai 20180326
# dump netflow records from nfsen server  and find the top 50 service endpoints and connecting source IPs and print out as csv

import csv
import sys
from collections import Counter
import subprocess
import tempfile
from datetime import datetime

source_address=[]
source_port=[]
destination_address=[]
destination_port=[]
top_endpoints=[]
sockets=[]
THRESHOLD=50
result={}
summarized_result={}
collapsed_ip=[]



filename1 = datetime.now().strftime("%Y%m%d-%H%M%S")

flowaclout = open('/tmp/flowacl-'+filename1+'.out','w')
tempflows=tempfile.NamedTemporaryFile()

# in the future remotely query an nfsen server
subprocess.call(["/usr/local/bin/nfdump","-r","/data/nfcapd.current.27911","-q","-c","10000000","-o","fmt:%sa,%sp,%da,%dp","-6","net 10.24.0.0/15"],stdout=tempflows)

with open(tempflows.name,'r') as fake_csv:
    reader = csv.reader(fake_csv, delimiter=',', quoting=csv.QUOTE_NONE)
    for row in reader :
        for value in (row[0:1]) :
            source_address.append(value.replace(" ", ""))
        for value in (row[1:2]) :
            source_port.append(value.replace(" ", ""))
        for value in (row[2:3]) :
            destination_address.append(value.replace(" ", ""))
        for value in (row[3:4]) :
            destination_port.append(value.replace(" ", ""))

tempflows.close()

for i in range(0,len(source_address)) :
    socket1 = source_address[i] + " " + source_port[i]
    socket2 = destination_address[i] + " " + destination_port[i]
    sockets.append(socket1)
    sockets.append(socket2)

from collections import Counter
socketcount=Counter(sockets).most_common(THRESHOLD)

for endpoint in socketcount :
    top_endpoints.append(endpoint[0])

for eachendpoint in top_endpoints :
    for index in range(0,len(sockets),2) :
        if eachendpoint == sockets[index] :
            connecting_socket=sockets[index+1].split(' ')
            endpoint_client_ip=connecting_socket[0]
            if not eachendpoint in result :
                result[eachendpoint]=[]
                firstoctet, secondoctet, thirdoctect,fourthoctect = endpoint_client_ip.split('.')
                fourthoctect="0"
                new_endpoint_client_ip=str.join(".",(firstoctet,secondoctet,thirdoctect,fourthoctect))
                result[eachendpoint].append(new_endpoint_client_ip)
            else :
                firstoctet, secondoctet, thirdoctect,fourthoctect = endpoint_client_ip.split('.')
                fourthoctect="0"
                new_endpoint_client_ip=str.join(".",(firstoctet,secondoctet,thirdoctect,fourthoctect))
                result[eachendpoint].append(new_endpoint_client_ip)
    for index in range(1,len(sockets),2) :
        if eachendpoint == sockets[index] :
            connecting_socket=sockets[index-1].split(' ')
            endpoint_client_ip=connecting_socket[0]
            if not eachendpoint in result :
                result[eachendpoint]=[]
                firstoctet, secondoctet, thirdoctect,fourthoctect = endpoint_client_ip.split('.')
                fourthoctect="0"
                new_endpoint_client_ip=str.join(".",(firstoctet,secondoctet,thirdoctect,fourthoctect))
                result[eachendpoint].append(new_endpoint_client_ip)
            else :
                firstoctet, secondoctet, thirdoctect,fourthoctect  = endpoint_client_ip.split('.')
                fourthoctect="0"
                new_endpoint_client_ip=str.join(".",(firstoctet,secondoctet,thirdoctect,fourthoctect))
                result[eachendpoint].append(new_endpoint_client_ip)


for key,value in result.items() :
    value.sort()
    uniqvalue=list(set(value))
    uniqvalue.sort()
    flowaclout.write(key+' : ')
    for sourcenetwork in uniqvalue :
        flowaclout.write(sourcenetwork+", ")
    flowaclout.write("\n\n")
