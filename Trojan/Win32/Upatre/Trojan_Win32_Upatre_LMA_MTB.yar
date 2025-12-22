
rule Trojan_Win32_Upatre_LMA_MTB{
	meta:
		description = "Trojan:Win32/Upatre.LMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f af c7 99 8d 71 10 f7 fe 0f b7 95 b4 84 fe ff 03 15 ?? ?? ?? ?? 0f af d1 03 c2 0f af 85 b0 84 fe ff 89 85 b0 84 fe ff } //10
		$a_03_1 = {8b 85 b0 84 fe ff d1 e8 0f af 05 ?? ?? ?? ?? 0f b7 d7 0f af d1 03 c2 0f af 85 b0 84 fe ff 89 85 b0 84 fe ff } //20
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*20) >=30
 
}