
rule Trojan_Win32_Upatre_SX_MTB{
	meta:
		description = "Trojan:Win32/Upatre.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {99 8d 76 51 f7 fe 8b b5 a4 fe ff ff 89 45 f4 b8 ?? ?? ?? ?? f7 65 c0 0f b7 45 ec c1 ea ?? 89 55 b0 89 45 d8 0f b6 55 e4 } //3
		$a_01_1 = {8b 5d e8 8b 45 ac 2b d1 2b 55 d4 40 8d 54 1a 02 0f af 55 ec 89 45 ac } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}