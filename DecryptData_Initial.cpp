// DecryptData.cpp
//
// THis file uses the input data and key information to decrypt the input data
//

#include "Main.h"

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
				xor al, 000110001b

			//#C Nibble Rotate Right 1 3A -> 95
				xor edx, edx	//Clear
				xor ecx, ecx	//Clear
				mov cl, al		//Copy

				and al, 0F0h	//High Bit 
				//shr al, 4		//Place into Nibble Low
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

