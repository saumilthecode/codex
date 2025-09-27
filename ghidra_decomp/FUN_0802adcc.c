
undefined4 FUN_0802adcc(uint param_1)

{
  longlong lVar1;
  int iVar2;
  uint *puVar3;
  undefined4 uVar4;
  uint uVar5;
  uint *puVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  int iVar10;
  int iVar11;
  
  puVar3 = (uint *)FUN_0802adc4();
  iVar2 = DAT_0802af2c;
  if ((int)param_1 < 0x7b2) {
    uVar4 = 0;
  }
  else {
    puVar3[1] = param_1;
    iVar7 = (param_1 - 0x7b2) * 0x16d + ((int)(param_1 - 0x7b1) >> 2) +
            (int)(param_1 - 0x76d) / -100 + (param_1 - 0x641) / 400;
    puVar6 = puVar3;
    do {
      uVar9 = puVar6[5];
      if ((char)puVar6[2] == 'J') {
        if ((((param_1 & 3) == 0) && (param_1 != ((int)param_1 / 100) * 100)) ||
           (param_1 == ((int)param_1 / 400) * 400)) {
          if ((int)uVar9 < 0x3c) {
            iVar10 = 0;
          }
          else {
            iVar10 = 1;
          }
        }
        else {
          iVar10 = 0;
        }
        iVar10 = iVar7 + uVar9 + iVar10 + -1;
      }
      else if ((char)puVar6[2] == 'D') {
        iVar10 = iVar7 + uVar9;
      }
      else {
        if (((param_1 & 3) == 0) && (param_1 != ((int)param_1 / 100) * 100)) {
          uVar5 = 1;
        }
        else {
          uVar5 = (uint)((int)param_1 % 400 == 0);
        }
        iVar8 = 0;
        iVar10 = iVar7;
        while( true ) {
          iVar8 = iVar8 + 1;
          iVar11 = *(int *)((-uVar5 & 0x30) + DAT_0802af30 + iVar8 * 4);
          if ((int)puVar6[3] <= iVar8) break;
          iVar10 = iVar10 + iVar11;
        }
        iVar8 = uVar9 - (iVar10 + 4) % 7;
        if (iVar8 < 0) {
          iVar8 = iVar8 + 7;
        }
        for (iVar8 = iVar8 + (puVar6[4] - 1) * 7; iVar11 <= iVar8; iVar8 = iVar8 + -7) {
        }
        iVar10 = iVar10 + iVar8;
      }
      lVar1 = (longlong)iVar10 * (longlong)iVar2 + (longlong)(int)puVar6[6];
      uVar9 = (uint)lVar1;
      uVar5 = puVar6[10];
      puVar6[8] = uVar9 + uVar5;
      puVar6[9] = (int)((ulonglong)lVar1 >> 0x20) + ((int)uVar5 >> 0x1f) + (uint)CARRY4(uVar9,uVar5)
      ;
      puVar6 = puVar6 + 10;
    } while (puVar3 + 0x14 != puVar6);
    uVar5 = puVar3[9];
    uVar9 = puVar3[0x13];
    *puVar3 = (uint)((int)((uVar5 - uVar9) - (uint)(puVar3[8] < puVar3[0x12])) < 0 !=
                    (SBORROW4(uVar5,uVar9) !=
                    SBORROW4(uVar5 - uVar9,(uint)(puVar3[8] < puVar3[0x12]))));
    uVar4 = 1;
  }
  return uVar4;
}

