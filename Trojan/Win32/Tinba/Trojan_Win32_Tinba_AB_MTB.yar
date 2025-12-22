
rule Trojan_Win32_Tinba_AB_MTB{
	meta:
		description = "Trojan:Win32/Tinba.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 8b 85 72 ff ff ff 66 25 ?? ?? 66 89 85 72 ff ff ff 8a 8d 1b ff ff ff f6 d9 0f b6 55 e7 88 8d 1b ff ff ff 0f b6 94 15 75 ff ff ff c7 45 a0 00 00 00 00 89 d6 83 ee } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}