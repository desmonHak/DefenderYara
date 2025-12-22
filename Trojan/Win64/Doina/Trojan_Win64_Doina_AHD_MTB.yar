
rule Trojan_Win64_Doina_AHD_MTB{
	meta:
		description = "Trojan:Win64/Doina.AHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffff82 00 ffffff82 00 04 00 00 "
		
	strings :
		$a_03_0 = {4c 2b c1 66 90 90 0f b7 02 48 8d 52 ?? 66 41 89 44 10 fe 66 85 c0 75 ?? 48 8d 8c 24 80 04 00 00 48 83 e9 } //30
		$a_01_1 = {52 58 53 5f 52 41 48 55 67 74 4c 34 77 46 44 4d 48 4d 78 78 63 } //50 RXS_RAHUgtL4wFDMHMxxc
		$a_81_2 = {42 72 61 76 65 5f 50 68 61 6e 74 6f 6d } //40 Brave_Phantom
		$a_01_3 = {5c 43 6f 6d 6f 64 6f 5c 44 72 61 67 6f 6e 5c 55 73 65 72 20 44 61 74 61 5c 4c 6f 63 61 6c 20 53 74 61 74 65 } //10 \Comodo\Dragon\User Data\Local State
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*50+(#a_81_2  & 1)*40+(#a_01_3  & 1)*10) >=130
 
}