#!/usr/bin/python3

import subprocess, sys, re, argparse
import socket, struct
import threading

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

solaris_ttl = 254
windows_ttl = 128
linux_ttl = 64

cidr_pattern = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$")
threads = []
hosts_up = []

def send_icmp_echo(target_ip, args):
	target_ip = str(target_ip[0])+"."+str(target_ip[1])+"."+str(target_ip[2])+"."+str(target_ip[3])
	#print(target_ip)
	timeout = 0
	if args.timeout == '0':
		timeout = 5
	elif args.timeout == '1':
		timeout = 2
	elif args.timeout == '2':
		timeout = 1
	elif args.timeout == '3':
		timeout = 0.2
	elif args.timeout == '4':
		timeout = 0.1
	elif args.timeout == '5':
		timeout = 0.05
	cmd = "timeout " + str(timeout) + " bash -c \"ping " + target_ip + " | head -n2 | tail -n1 | cut -d ' ' -f 6 | cut -d '=' -f 2\""
	ttl = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	if len(str(ttl.stdout)) > 3 and "Unreachable" not in str(ttl.stdout) and "0 received" not in str(ttl.stdout):
		#error de time to live exceded
		if str(ttl.stdout)[2:-3] != "live":
			ttl = int(str(ttl.stdout)[2:-3])
			if args.os_detection == True:
				hosts_up.append([target_ip, ttl])
			else:
				hosts_up.append(target_ip)
			if args.verbose == True:
				if args.os_detection == True:
					print(bcolors.OKCYAN + "[v]" + bcolors.ENDC + "\tHost up: " + target_ip + bcolors.OKBLUE + " - " + bcolors.ENDC + str(ttl))
				else:
					print(bcolors.OKCYAN + "[v]" + bcolors.ENDC + "\tHost up: " + target_ip)


def sort_key(item):
	sort_string = ""
	if  isinstance(item, str):
		sort_string = item
	else:
		sort_string = str(item[0])
	sort_string = [int(x) for x in sort_string.split(".")]

	return(sort_string)

def show_output():
	hosts_up.sort(key=sort_key)
	for host in hosts_up:
		if args.os_detection == False:
			print(bcolors.OKGREEN + "[+] " + bcolors.ENDC + host + bcolors.OKGREEN)
		else:
			ttl = host[1]
			if ttl > solaris_ttl:
				print(bcolors.OKGREEN + "[+] " + bcolors.ENDC + host[0] + bcolors.OKBLUE + " - " + bcolors.ENDC +"unknown")
			if ttl > windows_ttl and ttl <= solaris_ttl:
				print(bcolors.OKGREEN + "[+] " + bcolors.ENDC + host[0] + bcolors.OKBLUE + " - " + bcolors.ENDC +"solaris")
			elif ttl > linux_ttl and ttl <= windows_ttl:
				print(bcolors.OKGREEN + "[+] " + bcolors.ENDC + host[0] + bcolors.OKBLUE + " - " + bcolors.ENDC + "windows")
			elif ttl <= linux_ttl:
				print(bcolors.OKGREEN + "[+] " + bcolors.ENDC + host[0] + bcolors.OKBLUE + " - " + bcolors.ENDC + "linux")

def main(argv):
	try:
		cidrs = []
		if args.ips:
			args.ips = args.ips.split(",")

			for ip in args.ips:
				ip = ip.replace("'", "")
				print(ip)
				if '/' not in ip:
					ip += "/32"
				print(ip)

				if not cidr_pattern.match(ip):
					print("Input {} does not match cidr".format(ip))
					exit(1)
				else:
					cidrs.append(ip)
		if args.inputfile:
			for line in args.inputfile:
				line = line.replace("\n", "").replace("'", "")
				if '/' not in line:
					line += "/32"
				if not cidr_pattern.match(line):
					print("Input {} does not match cidr".format(line))
					exit(1)
				else:
					cidrs.append(line)

		if args.verbose:
			print(bcolors.OKCYAN + "[v]" + bcolors.ENDC  + " Targets to scan -> " + ', '.join(cidrs))
			print(bcolors.OKCYAN + "[v]" + bcolors.ENDC + " Scan started...")

		for cidr in cidrs:
			network, bits = cidr.split('/')
			netmask = socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << (32-int(bits)))))
			
			network = [int(x) for x in network.split(".")]
			netmask = [int(x) for x in netmask.split(".")]
			num_hosts = pow(2, 32-int(bits))
			for i in range(len(network)):
				network[i] = network[i]&netmask[i]

			if args.verbose:
				print(bcolors.OKCYAN + "[v]" + bcolors.ENDC + " network -> " + str(network[0]) + "." + str(network[1]) + "." + str(network[2]) + "." + str(network[3]))
				print(bcolors.OKCYAN + "[v]" + bcolors.ENDC + " netmask -> " + str(netmask[0]) + "." + str(netmask[1]) + "." + str(netmask[2]) + "." + str(netmask[3]))
				print(bcolors.OKCYAN + "[v]" + bcolors.ENDC + " hosts to scan ->", num_hosts)

			hosts = [0,0,0,0]
			for i in range(num_hosts):
				target_ip = [network[0]+hosts[0], network[1]+hosts[1], network[2]+hosts[2], network[3]+hosts[3]]
				string = "thread-"+str(i)
				t = threading.Thread(target=send_icmp_echo, args=(target_ip, args, ))
				threads.append(t)
				t.start()
				if hosts[3] < 255:
					hosts[3] += 1
				else:
					hosts[3] = 0
					if hosts[2] < 255:
						hosts[2] += 1
					else:
						hosts[2] = 0
						if hosts[1] < 255:
							hosts[1] += 1
						else:
							hosts[1] = 0
							if hosts[0] < 255:
								hosts[0] += 1

			#wait for all threads to finish
			for i in range(len(threads)):
				threads[i].join()
		if args.verbose:
			print(bcolors.OKCYAN + "[v]" + bcolors.ENDC + " Scan finished")
			
		show_output()

		
		if args.outputfile:
			for host in hosts_up:
				if isinstance(hosts_up[0], str):
					args.outputfile.write(host + "\n")
				else:
					args.outputfile.write(host[0] + "\n")

	except KeyboardInterrupt:
		print("\n"+bcolors.FAIL + "[-] " + bcolors.ENDC + "Scan stopped")

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="GET NMAP XML FILE INFORMATION")

	parser.add_argument('-v', '--verbose', action='store_true', help="Verbose mode")
	parser.add_argument('-i', '--inputfile', type=argparse.FileType('r'), help="Input file of ips")
	parser.add_argument('-o', '--outputfile', type=argparse.FileType('w'), help="Ouptut file")
	parser.add_argument('-O', '--os_detection', action='store_true', help="OS detection (TTL).")
	parser.add_argument('-T', '--timeout', choices=['0','1','2','3','4','5'], default='3', help="Timing. Higher number means faster but may cause undetections.")
	parser.add_argument('ips', nargs='?', type=ascii, help="Ips to scan (CIDR)")

	args = parser.parse_args()
	if args.inputfile == None and (args.ips == None or len(args.ips) == 0):
		print("You must specify ips or input file")

	print(args)
	main(args)
