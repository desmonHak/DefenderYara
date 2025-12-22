
rule Trojan_Win32_ChChes_GVA_MTB{
	meta:
		description = "Trojan:Win32/ChChes.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b f0 8b 44 24 08 83 c4 04 33 c9 85 f6 7e 11 8a 14 01 80 ea 24 80 f2 25 88 14 01 41 3b ce 7c ef } //2
		$a_01_1 = {8a 14 31 80 ea 24 80 f2 25 88 14 31 41 3b c8 7c ef } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}