
rule PWS_Win64_SharkStealer_A{
	meta:
		description = "PWS:Win64/SharkStealer.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 73 74 61 72 74 70 6f 6c 6c 69 6e 67 } //1 main.startpolling
		$a_01_1 = {6d 61 69 6e 2e 66 65 74 63 68 61 6e 64 64 65 63 72 79 70 74 } //1 main.fetchanddecrypt
		$a_01_2 = {6d 61 69 6e 2e 64 65 74 65 63 74 63 6f 69 6e } //1 main.detectcoin
		$a_01_3 = {6d 61 69 6e 2e 62 6c 79 61 64 64 5f 67 65 74 2e } //1 main.blyadd_get.
		$a_01_4 = {30 78 63 32 63 32 35 37 38 34 45 37 38 41 65 45 34 43 32 43 62 31 36 64 34 30 33 35 38 36 33 32 45 64 32 37 65 65 61 } //1 0xc2c25784E78AeE4C2Cb16d40358632Ed27eea
		$a_01_5 = {64 61 74 61 2d 73 65 65 64 2d 70 72 65 62 73 63 2d 32 2d 73 31 2e 62 69 6e 61 6e 63 65 2e 6f 72 67 } //1 data-seed-prebsc-2-s1.binance.org
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}