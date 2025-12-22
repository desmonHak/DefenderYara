
rule Trojan_Win32_Exnet_GVA_MTB{
	meta:
		description = "Trojan:Win32/Exnet.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c8 83 c4 08 8d 71 01 8a 11 41 84 d2 75 f9 33 d2 2b ce 74 09 80 34 02 bb 42 3b d1 72 f7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}