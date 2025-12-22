
rule Trojan_Win64_Nimbus_GVC_MTB{
	meta:
		description = "Trojan:Win64/Nimbus.GVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {2a 00 d7 c6 2a 00 0b de 2a 00 d7 } //1
		$a_01_1 = {14 08 00 14 64 0a 00 14 34 09 00 14 32 10 f0 0e e0 0c } //2
		$a_01_2 = {00 0f 32 0b 70 b4 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=4
 
}