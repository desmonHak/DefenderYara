
rule Trojan_Win64_LeakyStealer_YBE_MTB{
	meta:
		description = "Trojan:Win64/LeakyStealer.YBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 2b 41 30 03 49 ff c3 49 8b 82 80 00 00 00 48 ff c0 83 e0 3f 49 89 82 } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}
rule Trojan_Win64_LeakyStealer_YBE_MTB_2{
	meta:
		description = "Trojan:Win64/LeakyStealer.YBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 "
		
	strings :
		$a_01_0 = {42 65 61 63 6f 6e 20 73 74 61 72 74 69 6e 67 } //1 Beacon starting
		$a_01_1 = {50 6f 6c 79 6d 6f 72 70 68 69 73 6d 20 61 70 70 6c 69 65 64 } //1 Polymorphism applied
		$a_01_2 = {42 72 6f 77 73 65 72 20 68 69 73 74 6f 72 79 20 75 70 6c 6f 61 64 65 64 20 } //1 Browser history uploaded 
		$a_01_3 = {47 6f 74 20 70 65 72 73 69 73 74 65 6e 74 20 42 6f 74 20 49 44 20 66 72 6f 6d 20 76 6f 6c 75 6d 65 20 73 65 72 69 61 6c } //1 Got persistent Bot ID from volume serial
		$a_01_4 = {41 64 6d 69 6e 20 70 72 69 76 69 6c 65 67 65 73 } //1 Admin privileges
		$a_01_5 = {50 6f 6c 79 6d 6f 72 70 68 69 63 20 65 6e 67 69 6e 65 20 73 74 61 72 74 69 6e 67 } //1 Polymorphic engine starting
		$a_01_6 = {45 78 65 63 75 74 69 6e 67 20 64 6f 77 6e 6c 6f 61 64 65 64 20 66 69 6c 65 } //1 Executing downloaded file
		$a_01_7 = {42 69 74 63 6f 69 6e } //1 Bitcoin
		$a_01_8 = {45 6c 65 63 74 72 75 6d } //1 Electrum
		$a_01_9 = {45 78 6f 64 75 73 } //1 Exodus
		$a_01_10 = {41 74 6f 6d 69 63 20 57 61 6c 6c 65 74 } //1 Atomic Wallet
		$a_01_11 = {53 70 61 72 72 6f 77 20 57 61 6c 6c 65 74 } //1 Sparrow Wallet
		$a_01_12 = {42 69 74 50 61 79 20 57 61 6c 6c 65 74 } //1 BitPay Wallet
		$a_01_13 = {4f 70 65 72 61 20 53 6f 66 74 77 61 72 65 5c 4f 70 65 72 61 20 53 74 61 62 6c 65 5c 48 69 73 74 6f 72 79 } //1 Opera Software\Opera Stable\History
		$a_01_14 = {47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 48 69 73 74 6f 72 79 } //1 Google\Chrome\User Data\Default\History
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1) >=15
 
}