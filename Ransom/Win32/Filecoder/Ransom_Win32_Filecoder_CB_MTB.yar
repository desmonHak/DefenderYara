
rule Ransom_Win32_Filecoder_CB_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 d0 0f b6 08 8b 45 ?? 99 c1 ea ?? 01 d0 83 e0 ?? 29 d0 0f b6 54 05 ?? 8b 5d ?? 8b 45 ?? 01 d8 31 ca 88 10 83 45 } //3
		$a_01_1 = {89 45 ec 8d 45 b4 89 44 24 04 8b 45 ec 89 04 24 e8 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}