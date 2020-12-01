// DecryptData.cpp
//
// THis file uses the input data and key information to decrypt the input data
//

#include "Main.h"

void decryptData_03(char* data, int sized)
{
	int resulti = 0;

	__asm
	{
		//Keep the local variable
		mov eax, data //Keep the parameter before setting up the stack frame
		mov ebx, gNumRounds
		mov ecx, sized
		mov edx, ebp

		//Set up the stack frame
		push ebp
		mov ebp, esp
		sub esp, 40

		//Store the parameter and initial value in a local variable		
		mov dword ptr[ebp - 4], eax//Data
		mov dword ptr[ebp - 8], ecx//DataLength

		//MILESTONE #3 - gNumRounds
		dec ebx
		mov dword ptr[ebp - 28], ebx
		inc ebx
		mov dword ptr[ebp - 32], ebx
			
			//MILESTONE #3 - Loop
		L1: //for( round = 0; round < #rounds; round++)
			dec dword ptr[ebp - 32] // round++ (Really its gNumRound--)

			//Save starting index as local variable
			lea	esi, gPasswordHash //get the starting address of the password hash
			xor eax, eax //clear eax
			xor edx, edx //clear edx
			xor ecx, ecx //clear ecx
			mov ebx, dword ptr[ebp - 32] //Get Round

			//MILESTONE #3 - Starting_index[round] = gPasswordHash[0+round*4] * 256 + gPasswordHash[1+round*4]; 
			mov al, byte ptr[esi + ebx * 4] //get first byte of password hash
			mov cl, byte ptr[esi + 1 + ebx * 4] //get the second byte of the password hash
			imul eax, 256 //Multiply first byte by 256
			add eax, ecx //add the second byte
			mov dword ptr[ebp - 16], eax //store Starting_Index in a local variable


			xor eax, eax //clear eax
			xor ecx, ecx //clear ecx
			//MILESTONE #3 - hop_count [round] = gPasswordHash[2+round*4] * 256 + gPasswordHash[3+round*4]; 
			mov al, byte ptr[esi + 2 + ebx * 4] //get 3rd byte of password hash
			mov cl, byte ptr[esi + 3 + ebx * 4] //get the 4th byte of the password hash
			imul eax, 256 //Multiply first byte by 256
			add eax, ecx //add the second byte
			mov dword ptr[ebp - 36], eax //store hop_count in a local variable
			
			//MILESTONE #3 if(hop_count == 0) hop_count = 0xFFFF; 
			cmp eax, 0
			je IF1
			jmp ELSE1
			IF1:
				mov dword ptr[ebp - 36], 00000FFFFh
			ELSE1:

			//MILESTONE #3 index = Starting_index[round];
			mov eax, dword ptr[ebp - 16] //Get Starting Index
			mov dword ptr[ebp - 40], eax //index = Starting Index

			//Get the gkey pointer
			mov esi, gptrKey
			mov dword ptr[ebp - 20], esi //store the key pointer

			//Get the gEncodeTable pointer
			lea esi, gDecodeTable
			mov dword ptr[ebp - 24], esi

			xor ebx, ebx //Loop Variable (Offset) Stored at EBX

			//Loop over the data buffer
			L2:
				//Getting Byte
				mov eax, dword ptr[ebp - 4]  //get the data base pointer
				add eax, ebx //add the offset to the base
				mov dword ptr[ebp - 12], eax // Store Offset + Base
				mov al, byte ptr[eax] //move the current byte to a register
				and eax, 0000000FFh

			//MILESTONE #2 Begins HERE
				//Team 10 Decryption Order: BADCE

			//#B Reverse Bit order
				xor ecx, ecx	//Clear
				xor edx, edx	//Clear
				mov ecx, 8		//Set Count
				rev_loop :
				rcl al, 1		//Rotate Right
				rcr dl, 1		//Rotate Left
				loop rev_loop
				mov al, dl		//Move Result back into al

			//#A Table Lookup
				mov ecx, dword ptr[ebp - 24]	//Get table pointer
				add ecx, eax					//Add al to get correct position in table
				mov al, byte ptr[ecx]			//Get new byte from table	

			//#D Invert Bits 1 5 6
				xor al, 001100010b

				//#C Nibble Rotate Right 1 3A -> 95
				xor edx, edx	//Clear
				xor ecx, ecx	//Clear
				mov cl, al		//Copy

				and al, 0F0h	//High Bit 
				mov dl, al		//Move to DL for processing
				shl dl, 3		//Get rid of last 3 bits in DL
				shr al, 1		//Get rid of first bit in AL
				and al, 0F0h	//Dump that first bit
				add al, dl		//Put the "First bit" back into AL's Last bit slot

				and cl, 00Fh	//Low Bit
				shl cl, 4		//Place into Nibble Low
				mov dl, cl		//Move to DL for processing
				shl dl, 3		//Get rid of last 3 bits in DL
				shr cl, 1		//Get rid of first bit in CL
				and cl, 0F0h	//Dump that first bit	
				add cl, dl		//Put the "First bit" back into AL's Last bit slot					

				shr cl, 4		//Put CL back into the Last Nibble
				add al, cl		//Combine the two Nibbles AL, CL

			//#E Rotate 3 Bits Right
				ror al, 3

			//MILESTONE #2 Ends HERE

					//Getting Key
				mov edx, dword ptr[ebp - 20] //get the key base pointer
				add edx, dword ptr[ebp - 40] //get the Index
				mov edx, dword ptr[edx] //move the current byte to a register
				and edx, 0000000FFh

				//XOR Byte with Key
				xor al, dl //xor the key and data byte

				//MILESTONE #3 Begins HERE
				//index = index + hop_count[round];
				mov edx, dword ptr[ebp - 40] //Index
				add edx, dword ptr[ebp - 36] //Hop count
				cmp edx, 65537 //if(index >= 65537)
				jge IF2
				jmp ELSE2
				IF2 :
					add edx, -65537 // index = index - 65537; 
				ELSE2 :
					mov dword ptr[ebp - 40], edx
				//MILESTONE #3 Ends HERE

					//Store the xor byte into the buffer				
				mov ecx, dword ptr[ebp - 12] // Retrieve Offset + Base
				mov byte ptr[ecx], al // Move the Result byte back into the data buffer

					//Increment and CMP for Loop.
				inc ebx //increment the offset
				cmp ebx, [ebp - 8] //compare to the data length
			jne L2 //Loop if more data needs to process

		//MILESTONE 3 - LOOP END; for( round = 0; round < #rounds; round++)
		nop //Testing
		cmp dword ptr[ebp - 32], 0 // Check to see if gNumRounds == 0
		jne L1

		//return stack frame
		mov esp, ebp
		pop ebp
	}

	return;
} // decryptData_03

void decryptData_02(char* data, int sized)
{
	int resulti = 0;

	__asm
	{
		//Keep the local variable
		mov eax, data //Keep the parameter before setting up the stack frame
		mov ecx, sized
		mov edx, ebp

		//Set up the stack frame
		push ebp
		mov ebp, esp
		sub esp, 24

		//Store the parameter and initial value in a local variable		
		mov dword ptr[ebp - 4], eax//Data
		mov dword ptr[ebp - 8], ecx//DataLength
		xor ebx, ebx //Loop Variable (Offset) Stored at EBX

		//Save starting index as local variable
		//starting_index = gPasswordHash[0] * 256 + gPasswordHash[1];
		lea	esi, gPasswordHash //get the starting address of the password hash
		xor eax, eax //clear eax
		xor edx, edx //clear edx
		xor ecx, ecx //clear ecx
		mov al, byte ptr[esi] //get first byte of password hash
		mov cl, byte ptr[esi + 1] //get the second byte of the password hash
		imul eax, 256 //Multiply first byte by 256
		add eax, ecx //add the second byte
		mov dword ptr[ebp - 16], eax //store in a local variable

		//Get the gkey pointer
		mov esi, gptrKey
		mov dword ptr[ebp - 20], esi //store the key pointer

		//Get the gEncodeTable pointer
		lea esi, gDecodeTable
		mov dword ptr[ebp - 24], esi

		//Loop over the data buffer
	enc_loop :
		//Getting Byte
		mov eax, dword ptr[ebp - 4]  //get the data base pointer
		add eax, ebx //add the offset to the base
		mov dword ptr[ebp - 12], eax // Store Offset + Base
		mov dl, byte ptr[eax] //move the current byte to a register
		mov al, dl
		and eax, 0000000FFh

		//MILESTONE #2 Begins HERE
			//Team 10 Decryption Order: BADCE

		//#B Reverse Bit order
			xor ecx, ecx	//Clear
			xor edx, edx	//Clear
			mov ecx, 8		//Set Count
			rev_loop :
			rcl al, 1		//Rotate Right
			rcr dl, 1		//Rotate Left
			loop rev_loop
			mov al, dl		//Move Result back into al

		//#A Table Lookup
			mov ecx, dword ptr[ebp - 24]	//Get table pointer
			add ecx, eax					//Add al to get correct position in table
			mov al, byte ptr[ecx]			//Get new byte from table	

		//#D Invert Bits 1 5 6
			xor al, 001100010b

		//#C Nibble Rotate Right 1 3A -> 95
			xor edx, edx	//Clear
			xor ecx, ecx	//Clear
			mov cl, al		//Copy

			and al, 0F0h	//High Bit 
			mov dl, al		//Move to DL for processing
			shl dl, 3		//Get rid of last 3 bits in DL
			shr al, 1		//Get rid of first bit in AL
			and al, 0F0h	//Dump that first bit
			add al, dl		//Put the "First bit" back into AL's Last bit slot

			and cl, 00Fh	//Low Bit
			shl cl, 4		//Place into Nibble Low
			mov dl, cl		//Move to DL for processing
			shl dl, 3		//Get rid of last 3 bits in DL
			shr cl, 1		//Get rid of first bit in CL
			and cl, 0F0h	//Dump that first bit	
			add cl, dl		//Put the "First bit" back into AL's Last bit slot					

			shr cl, 4		//Put CL back into the Last Nibble
			add al, cl		//Combine the two Nibbles AL, CL

		//#E Rotate 3 Bits Right
			ror al, 3

		//MILESTONE #2 Ends HERE

			//Getting Key
			mov edx, dword ptr[ebp - 20] //get the key base pointer
			add edx, dword ptr[ebp - 16] //get the Starting_index, NOTE: Will need to be Index come milestone 3
			mov edx, dword ptr[edx] //move the current byte to a register
			and edx, 0000000FFh

			//XOR Byte with Key
			xor al, dl //xor the key and data byte

				//Store the xor byte into the buffer				
			mov ecx, dword ptr[ebp - 12] // Retrieve Offset + Base
			mov byte ptr[ecx], al // Move the Result byte back into the data buffer

				//Increment and CMP for Loop.
			inc ebx //increment the offset
			cmp ebx, [ebp - 8] //compare to the data length
			jne enc_loop //Loop if more data needs to process

		//return stack frame
			mov esp, ebp
			pop ebp
	}

	return;
} // decryptData_02

void decryptData_01(char *data, int sized)
{
	__asm
	{
		//Keep the local variable
		mov eax, data //Keep the parameter before setting up the stack frame
		mov ecx, sized
		mov edx, ebp

		//Set up the stack frame
		push ebp
		mov ebp, esp
		sub esp, 20

		//Store the parameter and initial value in a local variable		
		mov dword ptr[ebp - 4], eax//Data
		mov dword ptr[ebp - 8], ecx//DataLength
		xor ebx, ebx //Loop Variable (Offset) Stored at EBX

		//Save starting index as local variable
		//starting_index = gPasswordHash[0] * 256 + gPasswordHash[1];
		lea	esi, gPasswordHash //get the starting address of the password hash
		xor eax, eax //clear eax
		xor edx, edx //clear edx
		xor ecx, ecx //clear ecx
		mov al, byte ptr[esi] //get first byte of password hash
		mov cl, byte ptr[esi + 1] //get the second byte of the password hash
		imul eax, 256 //Multiply first byte by 256
		add eax, ecx //add the second byte
		mov dword ptr[ebp - 16], eax //store in a local variable

		//Get the gkey pointer
		mov esi, gptrKey
		mov dword ptr[ebp - 20], esi //store the key pointer

		//Loop over the data buffer
		enc_loop :
				//Getting Byte
			mov eax, dword ptr[ebp - 4]  //get the data base pointer
			add eax, ebx //add the offset to the base
			mov dword ptr[ebp-12], eax // Store Offset + Base
			mov dl, byte ptr[eax] //move the current byte to a register

				//Getting Key
			mov eax, dword ptr[ebp - 20] //get the key base pointer
			add eax, dword ptr[ebp - 16] //get the Starting_index, NOTE: Will need to be Index come milestone 2
			mov eax, dword ptr[eax] //move the current byte to a register

				//XOR Byte with Key
			xor al, dl //xor the key and data byte

				//Store the xor byte into the buffer				
			mov ecx, dword ptr[ebp - 12] // Retrieve Offset + Base
			mov byte ptr[ecx], al // Move the Result byte back into the data buffer

				//Increment and CMP for Loop.
			inc ebx //increment the offset
			cmp ebx, [ebp - 8] //compare to the data length
			jne enc_loop //Loop if more data needs to process

			//return stack frame
		mov esp, ebp
		pop ebp
	}

	return;
} // decryptData_01

int decryptData(char *data, int dataLength)
{
	int resulti = 0;

	gdebug1 = 0;					
	gdebug2 = 0;					
	__asm {
		nop
	}

} // decryptData

