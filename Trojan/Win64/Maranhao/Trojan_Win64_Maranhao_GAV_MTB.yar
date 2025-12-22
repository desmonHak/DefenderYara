
rule Trojan_Win64_Maranhao_GAV_MTB{
	meta:
		description = "Trojan:Win64/Maranhao.GAV!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {77 79 43 67 5a 73 38 56 45 } //2 wyCgZs8VE
		$a_01_1 = {62 4b 63 48 58 54 39 62 66 } //1 bKcHXT9bf
		$a_01_2 = {6a 50 44 39 59 36 4e 55 72 } //1 jPD9Y6NUr
		$a_01_3 = {6c 75 53 61 36 6e 79 72 49 } //1 luSa6nyrI
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}