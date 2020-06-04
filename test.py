import csv
import socket
with open('b.txt') as f:
    with open('bb.csv', 'w') as ff:
        c = {}
        for line in f:
            # print(line)
            if line == ',\n':
                continue
            line = line.strip()
            # a, b = line.split(',')
            # print(a)
            # if a not in c:
            if line not in c:
                # aa = int().from_bytes(socket.inet_aton(a), 'big')
                # c[a] = {
                # c[a] = {
                #     'count': 1,
                #     'value': aa
                # }
                c[line] = 1
            else:
                # c[a]['count']+=1
                c[line] +=1
            # bb = int().from_bytes(socket.inet_aton(b), 'big')

        for key,value in c.items():
            # ff.write(f'{value["value"]},{key},{value["count"]}\n')
            ff.write(f'{key},{value}\n')