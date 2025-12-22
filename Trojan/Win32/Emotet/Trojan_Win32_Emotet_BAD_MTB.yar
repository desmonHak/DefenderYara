
rule Trojan_Win32_Emotet_BAD_MTB{
	meta:
		description = "Trojan:Win32/Emotet.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 04 31 41 3b ca 7c ?? 5e 8b e5 5d c3 69 05 ?? ?? ?? ?? fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? ?? ?? c1 e8 10 25 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}