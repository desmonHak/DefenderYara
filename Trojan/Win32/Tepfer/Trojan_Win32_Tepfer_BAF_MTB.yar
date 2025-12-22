
rule Trojan_Win32_Tepfer_BAF_MTB{
	meta:
		description = "Trojan:Win32/Tepfer.BAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c3 8a 00 f3 0f 10 e4 f3 0f 10 ed 90 90 90 90 34 56 8b 15 ?? ?? ?? ?? 03 d3 88 02 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}