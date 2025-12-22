
rule Ransom_Win64_Filecoder_AP_AMTB{
	meta:
		description = "Ransom:Win64/Filecoder.AP!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_80_0 = {76 73 73 61 64 6d 69 6e 64 65 6c 65 74 65 73 68 61 64 6f 77 73 2f 2f 61 6c 6c 2f 2f 71 75 69 65 74 } //vssadmindeleteshadows//all//quiet  3
		$a_01_1 = {54 75 73 20 61 72 63 68 69 76 6f 73 20 68 61 6e 20 73 69 64 6f 20 63 69 66 72 61 64 6f 73 } //3 Tus archivos han sido cifrados
		$a_01_2 = {68 6f 6c 61 20 73 6f 79 20 65 6c 20 54 4f 58 20 72 61 6e 73 6f 6d } //2 hola soy el TOX ransom
		$a_01_3 = {52 61 6e 73 6f 6d 20 63 6f 6d 70 6c 65 74 6f 2e 20 50 61 72 61 20 72 65 63 75 70 65 72 61 72 2c 20 65 6a 65 63 75 74 61 } //1 Ransom completo. Para recuperar, ejecuta
		$a_01_4 = {72 61 6e 73 6f 6d 2e 70 64 62 } //1 ransom.pdb
		$a_01_5 = {6c 65 65 6d 65 2e 74 78 74 } //1 leeme.txt
	condition:
		((#a_80_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}