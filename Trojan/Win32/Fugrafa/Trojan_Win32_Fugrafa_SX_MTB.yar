
rule Trojan_Win32_Fugrafa_SX_MTB{
	meta:
		description = "Trojan:Win32/Fugrafa.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 11 0f b6 85 6b ff ff ff 03 45 a4 03 85 50 ff ff ff 0f b7 4d 88 03 c1 83 c8 ?? 88 85 3f ff ff ff } //3
		$a_03_1 = {2b f2 0b f1 a1 ?? ?? ?? ?? 66 c1 fe ?? 66 c1 e6 ?? 03 ce 8b f8 c0 e9 ?? c0 e1 ?? 97 8b 5d bc 53 ff d0 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}