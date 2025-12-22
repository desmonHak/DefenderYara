
rule Trojan_Win32_Remcos_GXT_MTB{
	meta:
		description = "Trojan:Win32/Remcos.GXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b c1 33 d0 0f af 95 ?? ?? ?? ?? 69 85 ?? ?? ?? ?? 40 40 40 40 2b d0 88 95 } //5
		$a_03_1 = {2b d1 0f b6 85 ?? ?? ?? ?? 05 ?? ?? ?? ?? 33 c2 0f af 85 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}