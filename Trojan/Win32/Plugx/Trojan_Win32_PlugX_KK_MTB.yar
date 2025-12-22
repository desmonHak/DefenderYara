
rule Trojan_Win32_PlugX_KK_MTB{
	meta:
		description = "Trojan:Win32/PlugX.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 50 8d 8d ?? ?? ff ff 8b 55 f8 8b c6 8b 38 ff 57 ?? 8b 85 70 fe ff ff e8 ?? ?? ff ff 59 ff 45 f8 ff 4d f4 } //20
		$a_01_1 = {31 56 58 70 59 6a 58 58 36 35 52 68 73 65 66 31 53 41 35 33 4f 6e 31 55 69 46 31 54 58 76 33 59 73 63 55 53 } //10 1VXpYjXX65Rhsef1SA53On1UiF1TXv3YscUS
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}