
rule VirTool_Win64_Shelesz_A{
	meta:
		description = "VirTool:Win64/Shelesz.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 63 45 e7 8b 55 e7 83 c2 7d 33 54 85 f3 48 63 45 e7 89 54 85 f3 8b 45 e7 03 c7 89 45 e7 8b 45 e7 3b c7 ?? ?? 44 8b 4d fb 44 8b 45 f3 ba } //1
		$a_01_1 = {48 63 45 e7 8b 55 e7 83 c2 7c 33 54 85 fb 48 63 45 e7 89 54 85 fb 8b 45 e7 03 c7 89 45 e7 8b 45 e7 3b c7 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}