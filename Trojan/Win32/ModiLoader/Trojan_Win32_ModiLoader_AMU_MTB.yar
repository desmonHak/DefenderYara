
rule Trojan_Win32_ModiLoader_AMU_MTB{
	meta:
		description = "Trojan:Win32/ModiLoader.AMU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {50 6a 00 68 ff 0f 1f 00 e8 ?? ?? ?? ?? 8d 54 24 04 52 6a 04 68 ?? ?? ?? ?? 8d 54 24 0c 52 50 e8 ?? ?? ?? ?? 8b c3 59 5a 5f 5e 5b } //1
		$a_01_1 = {6a 00 6a 00 6a 00 6a 00 68 3c b0 45 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 68 4c b0 45 00 8d 45 fc } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}