
rule Trojan_Win32_BruteRatelShell_AA_MTB{
	meta:
		description = "Trojan:Win32/BruteRatelShell.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 e1 00 48 ff c8 88 02 48 31 fa 48 8d 5b 01 48 39 f3 75 ?? 48 29 f3 48 01 da 48 31 fa ff e2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}