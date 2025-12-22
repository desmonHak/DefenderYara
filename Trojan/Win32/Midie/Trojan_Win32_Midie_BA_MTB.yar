
rule Trojan_Win32_Midie_BA_MTB{
	meta:
		description = "Trojan:Win32/Midie.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d7 13 cf c1 ea ?? 0f a4 ef 10 33 c0 c1 e5 ?? 0b c7 0b d5 33 c1 33 54 24 ?? 33 ed 0b 6c 24 ?? 01 54 24 1c 13 e8 33 ff 89 6c 24 14 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}