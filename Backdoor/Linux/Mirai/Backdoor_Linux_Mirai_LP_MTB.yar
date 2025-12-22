
rule Backdoor_Linux_Mirai_LP_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.LP!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 64 6f 73 5f 75 64 70 5f 70 6b 74 5f 66 6c 6f 6f 64 } //1 ddos_udp_pkt_flood
		$a_01_1 = {64 64 6f 73 5f 75 64 70 5f 73 69 6d 70 6c 65 5f 66 6c 6f 6f 64 } //1 ddos_udp_simple_flood
		$a_01_2 = {64 64 6f 73 5f 75 64 70 5f 62 79 70 61 73 73 5f 66 6c 6f 6f 64 } //1 ddos_udp_bypass_flood
		$a_01_3 = {64 64 6f 73 5f 61 63 6b 5f 66 6c 6f 6f 64 } //1 ddos_ack_flood
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}