
rule Trojan_Win32_Upatre_AB_MTB{
	meta:
		description = "Trojan:Win32/Upatre.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ec 83 ec 10 8b 45 08 25 00 00 ff ff b9 4d 5a 00 00 ?? ?? 2d 00 00 01 00 66 39 08 ?? ?? 0f b7 48 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}