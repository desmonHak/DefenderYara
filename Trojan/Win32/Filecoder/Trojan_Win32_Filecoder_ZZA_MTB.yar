
rule Trojan_Win32_Filecoder_ZZA_MTB{
	meta:
		description = "Trojan:Win32/Filecoder.ZZA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b9 ff ff ff ff ba 01 00 00 00 e8 39 2e 06 00 83 7d f4 01 75 eb 8b 4d f8 8b 55 fc 49 89 c8 49 c1 e0 20 49 83 c8 02 31 c0 85 c9 0f 95 c0 49 0f 45 d0 48 83 c4 60 5d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}