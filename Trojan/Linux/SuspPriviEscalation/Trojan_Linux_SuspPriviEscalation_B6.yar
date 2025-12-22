
rule Trojan_Linux_SuspPriviEscalation_B6{
	meta:
		description = "Trojan:Linux/SuspPriviEscalation.B6,SIGNATURE_TYPE_CMDHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_00_0 = {73 00 65 00 64 00 20 00 2d 00 6e 00 } //2 sed -n
		$a_00_1 = {65 00 78 00 65 00 63 00 20 00 2f 00 62 00 69 00 6e 00 2f 00 62 00 61 00 73 00 68 00 } //2 exec /bin/bash
		$a_00_2 = {20 00 31 00 3e 00 26 00 30 00 } //2  1>&0
		$a_00_3 = {2f 00 65 00 74 00 63 00 2f 00 68 00 6f 00 73 00 74 00 73 00 } //2 /etc/hosts
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=8
 
}