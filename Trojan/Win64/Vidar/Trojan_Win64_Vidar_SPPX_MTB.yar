
rule Trojan_Win64_Vidar_SPPX_MTB{
	meta:
		description = "Trojan:Win64/Vidar.SPPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 20 20 20 20 20 20 20 10 00 00 00 00 b0 01 00 00 02 00 00 00 da 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 20 20 20 20 20 20 20 20 20 2c 00 00 00 c0 01 00 00 18 00 00 00 dc 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 2e 62 73 73 00 00 00 00 e0 a3 00 00 00 f0 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}