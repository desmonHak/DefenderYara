
rule Trojan_Win32_Tiny_AB_MTB{
	meta:
		description = "Trojan:Win32/Tiny.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 ec 1c 02 00 00 a1 e0 85 03 10 33 c4 89 84 24 18 02 00 00 8b 84 24 20 02 00 00 8b 40 14 b9 00 01 00 00 56 89 4c 24 0c 89 4c 24 10 85 c0 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}