
rule Trojan_Win32_Remcos_NJ_MTB{
	meta:
		description = "Trojan:Win32/Remcos.NJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {eb 0f 8b 8d 58 fc ff ff 83 c1 01 89 8d 58 fc ff ff 8b 95 5c fc ff ff 8b 85 58 fc ff ff 3b 42 18 0f 83 f9 } //2
		$a_01_1 = {f0 eb ff ff 8b 85 e0 fd ff ff 03 04 8a 89 85 54 fc ff } //1
		$a_01_2 = {33 32 5c 41 2e 44 4c 4c } //1 32\A.DLL
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}