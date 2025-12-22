
rule Trojan_Win32_Copak_BAD_MTB{
	meta:
		description = "Trojan:Win32/Copak.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 1a 09 c9 89 ce 88 1f 21 f1 81 ee 01 00 00 00 29 f1 81 c7 01 00 00 00 09 f1 89 ce 09 f6 81 c2 02 00 00 00 4e 09 f1 01 f1 39 c2 7e } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}