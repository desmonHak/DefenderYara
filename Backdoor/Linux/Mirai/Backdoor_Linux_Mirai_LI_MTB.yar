
rule Backdoor_Linux_Mirai_LI_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.LI!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 61 6d 65 6c 62 6f 61 74 2e 6e 2d 65 2e 6b 72 } //1 camelboat.n-e.kr
		$a_01_1 = {75 64 70 62 79 70 61 73 73 } //1 udpbypass
		$a_01_2 = {72 30 30 74 73 33 63 2d 6f 77 6e 65 64 2d 79 6f 75 } //1 r00ts3c-owned-you
		$a_01_3 = {74 74 70 3a 2f 2f 75 6e 6a 69 70 72 6f 78 79 2e 70 2d 65 2e 6b 72 3a 36 39 36 39 2f 62 69 6e 73 2f 78 38 36 20 2d 4f 20 2f 74 6d 70 2f 2e 75 6e 6a 69 } //1 ttp://unjiproxy.p-e.kr:6969/bins/x86 -O /tmp/.unji
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}