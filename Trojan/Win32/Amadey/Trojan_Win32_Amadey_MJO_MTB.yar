
rule Trojan_Win32_Amadey_MJO_MTB{
	meta:
		description = "Trojan:Win32/Amadey.MJO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 4a ff 83 e1 1e 0f b6 89 ?? ?? ?? ?? 32 8a ?? ?? ?? ?? 88 4c 10 ff 81 fa a9 39 06 00 74 1a 89 d1 83 e1 1f 0f b6 89 ?? ?? ?? ?? 32 8a ?? ?? ?? ?? 88 0c 10 83 c2 02 eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}