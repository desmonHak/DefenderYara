
rule Trojan_Win32_Azorult_BAH_MTB{
	meta:
		description = "Trojan:Win32/Azorult.BAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b f1 33 c6 03 d0 a1 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 88 10 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}