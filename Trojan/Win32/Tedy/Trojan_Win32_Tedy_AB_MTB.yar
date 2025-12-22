
rule Trojan_Win32_Tedy_AB_MTB{
	meta:
		description = "Trojan:Win32/Tedy.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 a9 00 80 0f 95 c0 8b 15 c0 97 6b 00 8b 12 32 82 d4 00 00 00 0f 84 fa 00 00 00 a1 14 f6 6b 00 8b 10 ff 52 08 a1 10 f6 6b 00 8b 58 08 4b 85 db 0f 8c ae 00 00 00 43 33 ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Tedy_AB_MTB_2{
	meta:
		description = "Trojan:Win32/Tedy.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {57 ff d6 68 ?? ?? ?? ?? ff b5 8c fb ff ff 89 85 94 fb ff ff ff d6 68 ?? ?? ?? ?? 57 89 85 74 fb ff ff ff d6 68 ?? ?? ?? ?? 57 89 85 78 fb ff ff ff d6 68 ?? ?? ?? ?? 57 89 85 ?? fb ff ff ff d6 68 ?? ?? ?? ?? 57 89 85 6c fb ff ff ff d6 68 ?? ?? ?? ?? 57 89 85 8c fb ff ff ff d6 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}