
rule DDoS_Linux_SAgnt_D_MTB{
	meta:
		description = "DDoS:Linux/SAgnt.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 74 74 61 63 6b 20 25 36 33 73 20 25 36 33 73 20 25 64 20 25 64 } //1 attack %63s %63s %d %d
		$a_01_1 = {75 64 70 2d 62 79 70 61 73 73 } //1 udp-bypass
		$a_01_2 = {69 63 6d 70 2d 66 6c 6f 6f 64 } //1 icmp-flood
		$a_01_3 = {74 63 70 2d 62 79 70 61 73 73 } //1 tcp-bypass
		$a_03_4 = {77 67 65 74 20 2d 71 4f 20 2f 74 6d 70 2f 75 70 64 20 68 74 74 70 3a [0-20] 2f 64 72 6f 70 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}