
rule Ransom_Win32_Qilin_AQI_MTB{
	meta:
		description = "Ransom:Win32/Qilin.AQI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 d6 89 d1 8b 54 24 30 8b 44 24 10 0f af ca f7 e2 01 ca 01 84 24 18 01 00 00 8b 4c 24 0c 8b 44 24 10 11 94 24 1c 01 00 00 0f af f1 f7 e1 01 f2 29 c7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}