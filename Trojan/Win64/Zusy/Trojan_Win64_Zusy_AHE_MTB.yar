
rule Trojan_Win64_Zusy_AHE_MTB{
	meta:
		description = "Trojan:Win64/Zusy.AHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffff97 00 ffffff97 00 06 00 00 "
		
	strings :
		$a_01_0 = {48 8d 44 24 50 45 31 c9 45 31 c0 48 89 44 24 48 48 8d 44 24 70 48 89 da 31 c9 48 89 44 24 40 48 c7 44 24 38 00 00 00 00 48 c7 44 24 30 00 00 00 00 c7 44 24 28 00 00 00 08 c7 44 24 20 00 00 00 00 ff 15 } //100
		$a_01_1 = {70 6f 77 65 72 73 68 65 6c 6c 20 20 2d 63 20 22 24 6e 3d 5b 53 79 73 74 65 6d 2e 4c 69 6e 71 2e 45 6e 75 6d 65 72 61 62 6c 65 5d 3a 3a 46 69 72 73 74 28 5b 63 68 61 72 5b 5d 5d 28 31 30 29 29 3b 69 72 6d } //50 powershell  -c "$n=[System.Linq.Enumerable]::First([char[]](10));irm
		$a_01_2 = {65 76 65 6e 74 2d 73 64 61 74 61 2d 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d } //1 event-sdata-microsoft.com
		$a_01_3 = {6c 6f 67 69 6e 6c 69 76 65 2d 6d 69 63 72 6f 73 6f 66 74 2e 6f 72 67 } //1 loginlive-microsoft.org
		$a_01_4 = {65 76 65 6e 74 2d 74 69 6d 65 2d 6d 69 63 72 6f 73 6f 66 74 2e 6f 72 67 } //1 event-time-microsoft.org
		$a_01_5 = {65 76 65 6e 74 2d 73 64 61 2d 74 61 2d 6d 69 63 72 6f 73 6f 66 74 2e 6c 69 76 65 } //1 event-sda-ta-microsoft.live
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*50+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=151
 
}