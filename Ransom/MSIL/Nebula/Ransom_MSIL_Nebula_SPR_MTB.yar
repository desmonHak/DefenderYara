
rule Ransom_MSIL_Nebula_SPR_MTB{
	meta:
		description = "Ransom:MSIL/Nebula.SPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {4e 00 65 00 62 00 75 00 6c 00 61 00 52 00 75 00 6e 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //2 NebulaRun.Properties.Resources
		$a_01_1 = {64 00 65 00 6c 00 73 00 65 00 6c 00 66 00 2e 00 62 00 61 00 74 00 } //1 delself.bat
		$a_01_2 = {4e 00 65 00 62 00 75 00 6c 00 61 00 20 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 6f 00 72 00 } //1 Nebula Decryptor
		$a_01_3 = {4e 00 65 00 62 00 75 00 6c 00 61 00 52 00 75 00 6e 00 2e 00 6e 00 65 00 62 00 75 00 6c 00 61 00 2e 00 70 00 6e 00 67 00 } //1 NebulaRun.nebula.png
		$a_01_4 = {2e 00 6e 00 62 00 6c 00 } //1 .nbl
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}