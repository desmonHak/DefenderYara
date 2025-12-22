
rule Ransom_Win32_Natas_PAGX_MTB{
	meta:
		description = "Ransom:Win32/Natas.PAGX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b7 d7 66 0f be 0c 10 b8 ff 00 00 00 66 33 cf 66 23 c8 0f b6 04 ?? ?? ?? ?? ?? 66 33 c8 47 66 89 0c 53 66 3b 3c f5 } //3
		$a_03_1 = {0f b7 ca 8a 04 08 32 04 f5 ?? ?? ?? ?? 32 c2 42 88 04 39 66 3b 14 f5 ?? ?? ?? ?? 72 dc } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}