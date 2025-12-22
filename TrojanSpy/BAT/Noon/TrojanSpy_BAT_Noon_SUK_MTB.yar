
rule TrojanSpy_BAT_Noon_SUK_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.SUK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {24 36 30 65 37 38 31 37 34 2d 30 35 35 38 2d 34 66 65 65 2d 39 31 64 31 2d 37 64 33 65 34 31 31 31 63 33 39 62 } //1 $60e78174-0558-4fee-91d1-7d3e4111c39b
		$a_81_1 = {47 61 6d 65 46 6f 6f 64 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 GameFood.Properties.Resources
		$a_81_2 = {44 65 73 65 6e 76 6f 6c 76 69 64 6f 20 70 6f 72 20 44 69 6f 67 6f 20 53 6f 75 7a 61 } //1 Desenvolvido por Diogo Souza
		$a_81_3 = {4a 6f 67 6f 47 6f 75 72 6d 65 74 } //1 JogoGourmet
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}