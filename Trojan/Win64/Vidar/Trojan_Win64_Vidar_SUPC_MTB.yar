
rule Trojan_Win64_Vidar_SUPC_MTB{
	meta:
		description = "Trojan:Win64/Vidar.SUPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 20 20 00 20 20 20 20 00 70 0d 00 00 10 00 00 00 e4 04 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 a8 03 00 00 00 80 0d 00 00 04 00 00 00 f4 04 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}