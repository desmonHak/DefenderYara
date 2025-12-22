
rule Trojan_Win32_Zusy_KK_MTB{
	meta:
		description = "Trojan:Win32/Zusy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 6a 01 6a 02 83 ec 0c 8b 44 24 14 83 c0 3c 8b 00 03 44 24 14 83 c0 78 85 c0 0f 84 aa 00 00 00 } //20
		$a_01_1 = {b6 12 00 d6 b6 12 00 e6 b6 12 00 fc b6 12 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}
rule Trojan_Win32_Zusy_KK_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a c3 f6 eb 32 45 13 8a cb c0 e1 02 32 ca 02 c1 00 44 1d f8 43 83 fb 08 } //20
		$a_01_1 = {8b 55 fc 30 0c 02 40 3b 45 0c } //10
		$a_01_2 = {70 63 6c 44 72 61 67 6f 76 2e 65 78 65 } //5 pclDragov.exe
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}
rule Trojan_Win32_Zusy_KK_MTB_3{
	meta:
		description = "Trojan:Win32/Zusy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c8 8d 47 01 33 ca 2b ca 80 f9 ?? 0f 45 c7 46 8b f8 3b f5 } //20
		$a_03_1 = {8b c8 33 ca 2b ca 8b 54 24 10 80 f9 ?? 8d 42 01 0f 45 c2 8b c8 8b 44 24 0c 40 89 4c 24 10 89 44 24 0c 3b c7 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}
rule Trojan_Win32_Zusy_KK_MTB_4{
	meta:
		description = "Trojan:Win32/Zusy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 85 b0 fe ff ff 00 00 00 00 8d 85 f0 fe ff ff 89 44 24 0c 8d 85 b0 fe ff ff 89 44 24 08 8b 45 10 c7 85 f0 fe ff ff 00 00 00 00 89 44 24 04 8b 45 0c 89 04 24 } //20
		$a_01_1 = {c7 41 78 00 00 00 00 83 c1 08 c7 41 74 00 00 00 00 39 ce } //10
		$a_01_2 = {e8 5d 10 00 00 b9 35 00 00 00 31 d2 f7 f1 8a 44 15 b2 88 04 33 46 eb e3 } //5
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}