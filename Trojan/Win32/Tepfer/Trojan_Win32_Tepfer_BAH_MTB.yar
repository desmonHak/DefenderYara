
rule Trojan_Win32_Tepfer_BAH_MTB{
	meta:
		description = "Trojan:Win32/Tepfer.BAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {5a 2b d0 03 f2 31 37 83 c3 04 83 c7 04 3b 5d e0 72 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}