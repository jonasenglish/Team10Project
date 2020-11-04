// EncryptData.cpp
//
// This file uses the input data and key information to encrypt the input data
//

#include "Main.h"

void encryptData_01(char *data, int datalength)
{
	int resulti = 0;

	__asm
	{
		//Keep the local variable
		mov eax, data //Keep the parameter before setting up the stack frame
		mov ecx, datalength
		mov edx, ebp

		//Set up the stack frame
		push ebp
		mov ebp, esp
		sub esp, 32

		//Store the parameter and initial value in a local variable		
		mov dword ptr[ebp - 4], eax//Data
		mov dword ptr[ebp - 8], ecx//DataLength
		mov dword ptr[ebp - 12], 0//loop variable

		//Save starting index as local variable
		//starting_index = gPasswordHash[0] * 256 + gPasswordHash[1];
		lea	esi, gPasswordHash //get the starting address of the password hash
		xor eax, eax //clear eax
		xor ecx, ecx //clear ecx
		mov al, byte ptr[esi] //get first byte of password hash
		mov cl, byte ptr[esi + 1] //get the second byte of the password hash
		imul eax, 256 //Multiply first byte by 256
		add eax, ecx //add the second byte
		mov dword ptr[ebp - 16], eax //store in a local variable

		//Get the gkey pointer
		mov esi, gptrKey
		mov dword ptr[ebp-20], esi //store the key pointer


		//Loop over the data buffer
		enc_loop:
				//Getting Byte
			mov eax, dword ptr[ebp - 4]  //get the data base pointer
			mov ecx, dword ptr[ebp - 12] //get the current offset
			add eax, ecx //add the offset to the base
			mov al, byte ptr[eax] //move the current byte to a register
			and eax, 00FFh  //mask the lower byte
			mov byte ptr[ebp-24], al //Store the data byte in a local variable
			
				//Getting Key
			mov eax, dword ptr[ebp - 20] //get the key base pointer
			mov ecx, dword ptr[ebp - 16] //get the Starting_index, NOTE: Will need to be Index come milestone 2
			add eax, ecx //add the offset to the base
			mov al, byte ptr[eax] //move the current byte to a register
			and eax, 00FFh //mask the lower byte
				
				//XOR Byte with Key
			mov ecx, dword ptr[ebp-24] //get the data byte from earlier
			xor eax, ecx //xor the key and data byte
			mov dword ptr[ebp-28], eax //store the result in a local variable

				//Store the xor byte into the buffer				
			mov eax, dword ptr[ebp - 4]//get the data base pointer
			mov ecx, dword ptr[ebp - 12]//get the current offset
			add eax, ecx //add the offset to the base
			mov ecx, dword ptr[ebp - 28] //get the byte from the local variable
			mov byte ptr[eax], cl //move the result byte back into the data buffer

				//Increment and CMP for Loop.
			inc	[ebp - 12] //increment the offset
			mov eax, [ebp-12] //move to register for comparison
			cmp eax, [ebp - 8] //compare to the data length
			jne enc_loop //Loop if more data needs to process

		//return stack frame
		mov esp, ebp
		pop ebp
	}

	return;
} // encryptData_01


int encryptData(char *data, int dataLength)
{
	int resulti = 0;

	gdebug1 = 0;					
	gdebug2 = 0;					
	__asm {
		nop
	}

	return resulti;
} // encryptData

