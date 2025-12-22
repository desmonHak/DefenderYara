
rule Trojan_Win32_Fareit_BB_MTB{
	meta:
		description = "Trojan:Win32/Fareit.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 08 32 1d ?? ?? ?? ?? 88 18 89 ff 90 90 89 c9 89 c9 ff 07 81 3f 96 6f 00 00 75 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}