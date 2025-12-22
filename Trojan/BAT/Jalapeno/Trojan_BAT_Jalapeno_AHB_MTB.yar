
rule Trojan_BAT_Jalapeno_AHB_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 17 6f 23 00 00 0a 25 16 6f 22 00 00 0a 28 25 00 00 0a 25 2d 03 26 2b 05 28 35 00 00 0a } //50
		$a_01_1 = {68 61 74 65 72 2f 63 65 63 68 6f 2e 65 78 65 } //30 hater/cecho.exe
		$a_01_2 = {68 61 74 65 72 2f 6c 61 6e 64 2e 7a 69 70 } //20 hater/land.zip
	condition:
		((#a_01_0  & 1)*50+(#a_01_1  & 1)*30+(#a_01_2  & 1)*20) >=100
 
}