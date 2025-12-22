
rule Trojan_Win64_Convagent_AHB_MTB{
	meta:
		description = "Trojan:Win64/Convagent.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_03_0 = {66 44 0f d6 bc 24 10 01 00 00 c6 44 24 37 00 44 0f 11 bc 24 e0 00 00 00 44 0f 11 bc 24 f0 00 00 00 44 0f 11 bc 24 00 01 00 00 48 c7 84 24 e8 00 00 00 ?? 00 00 00 48 8d 15 } //20
		$a_03_1 = {48 89 44 24 78 48 89 5c 24 60 48 89 4c 24 68 44 0f 11 7c 24 38 44 0f 11 7c 24 48 48 8d 44 24 38 bb ?? 00 00 00 48 89 d9 e8 } //10
		$a_01_2 = {79 45 76 44 62 46 74 53 61 78 58 35 38 50 4b 75 64 31 5f 52 2f 53 2d 51 4f 75 54 33 78 69 6c 33 68 37 38 6e 42 35 53 33 46 2f 6b 7a 56 30 30 78 31 39 53 74 59 49 49 33 30 64 69 36 75 63 2f 6d 68 43 55 70 52 5a 63 75 42 71 4b 5f 6c 4f 57 78 6d 51 5f } //5 yEvDbFtSaxX58PKud1_R/S-QOuT3xil3h78nB5S3F/kzV00x19StYII30di6uc/mhCUpRZcuBqK_lOWxmQ_
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}