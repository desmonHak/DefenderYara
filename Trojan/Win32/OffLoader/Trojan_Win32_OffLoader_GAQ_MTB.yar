
rule Trojan_Win32_OffLoader_GAQ_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.GAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? 1d 00 ?? ?? 0e 00 00 64 36 00 ?? ?? ?? ?? be 9b 0e 00 00 3e 0d 00 ?? ?? ?? ?? 00 00 01 00 0d } //8
	condition:
		((#a_03_0  & 1)*8) >=8
 
}