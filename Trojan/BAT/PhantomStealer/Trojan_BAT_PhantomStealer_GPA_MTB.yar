
rule Trojan_BAT_PhantomStealer_GPA_MTB{
	meta:
		description = "Trojan:BAT/PhantomStealer.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 "
		
	strings :
		$a_01_0 = {51 42 58 74 58 } //1 QBXtX
		$a_01_1 = {73 74 61 72 74 75 70 72 65 67 } //1 startupreg
		$a_01_2 = {63 61 6d 69 6e 68 6f 76 62 73 } //1 caminhovbs
		$a_01_3 = {6e 61 6d 65 76 62 73 } //1 namevbs
		$a_01_4 = {6e 65 74 66 72 61 6d 65 77 6f 72 6b } //1 netframework
		$a_01_5 = {6e 61 74 69 76 6f } //1 nativo
		$a_01_6 = {6e 6f 6d 65 6e 61 74 69 76 6f } //1 nomenativo
		$a_01_7 = {70 65 72 73 69 74 65 6e 63 69 61 } //1 persitencia
		$a_01_8 = {63 61 6d 69 6e 68 6f } //1 caminho
		$a_01_9 = {6e 6f 6d 65 64 6f 61 72 71 75 69 76 6f } //1 nomedoarquivo
		$a_01_10 = {6d 69 6e 75 74 6f 73 } //1 minutos
		$a_01_11 = {74 61 73 6b 6e 61 6d 65 } //1 taskname
		$a_01_12 = {76 6d 4e 61 6d 65 } //1 vmName
		$a_01_13 = {75 72 6c 5f 75 61 63 } //1 url_uac
		$a_01_14 = {63 6f 6d 61 6e 64 75 61 63 } //1 comanduac
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1) >=15
 
}