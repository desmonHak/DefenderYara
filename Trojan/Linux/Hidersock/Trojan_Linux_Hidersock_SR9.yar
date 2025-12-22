
rule Trojan_Linux_Hidersock_SR9{
	meta:
		description = "Trojan:Linux/Hidersock.SR9,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 0d 00 00 "
		
	strings :
		$a_80_0 = {73 6f 63 6b 65 74 } //socket  1
		$a_80_1 = {69 6f 63 74 6c } //ioctl  1
		$a_80_2 = {44 72 6f 70 70 69 6e 67 20 74 6f 20 72 6f 6f 74 20 73 68 65 6c 6c } //Dropping to root shell  2
		$a_80_3 = {48 69 64 69 6e 67 20 50 49 44 20 25 75 } //Hiding PID %u  2
		$a_80_4 = {48 69 64 69 6e 67 20 54 43 50 76 34 20 70 6f 72 74 20 25 68 75 } //Hiding TCPv4 port %hu  2
		$a_80_5 = {48 69 64 69 6e 67 20 54 43 50 76 36 20 70 6f 72 74 20 25 68 75 } //Hiding TCPv6 port %hu  2
		$a_80_6 = {48 69 64 69 6e 67 20 55 44 50 76 34 20 70 6f 72 74 20 25 68 75 } //Hiding UDPv4 port %hu  2
		$a_80_7 = {48 69 64 69 6e 67 20 55 44 50 76 36 20 70 6f 72 74 20 25 68 75 } //Hiding UDPv6 port %hu  2
		$a_80_8 = {48 69 64 69 6e 67 20 66 69 6c 65 2f 64 69 72 20 25 73 } //Hiding file/dir %s  2
		$a_80_9 = {48 69 64 69 6e 67 20 6e 65 74 77 6f 72 6b 20 50 52 4f 4d 49 53 43 20 66 6c 61 67 } //Hiding network PROMISC flag  2
		$a_80_10 = {53 69 6c 65 6e 74 6c 79 20 70 72 6f 68 69 62 69 74 69 6e 67 20 6d 6f 64 75 6c 65 20 6c 6f 61 64 69 6e 67 } //Silently prohibiting module loading  2
		$a_80_11 = {6b 69 6c 6c 61 62 6c 65 20 50 72 6f 63 65 73 73 20 25 68 75 } //killable Process %hu  2
		$a_80_12 = {48 69 64 65 20 4d 6f 64 75 6c 65 } //Hide Module  2
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2+(#a_80_6  & 1)*2+(#a_80_7  & 1)*2+(#a_80_8  & 1)*2+(#a_80_9  & 1)*2+(#a_80_10  & 1)*2+(#a_80_11  & 1)*2+(#a_80_12  & 1)*2) >=6
 
}