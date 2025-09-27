
byte * FUN_0802a8ba(int param_1,byte *param_2)

{
  byte *pbVar1;
  byte *pbVar2;
  byte bVar3;
  byte *pbVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  bool bVar9;
  
  uVar6 = (uint)*param_2;
  bVar9 = uVar6 == 0x5e;
  if (bVar9) {
    uVar6 = (uint)param_2[1];
    pbVar4 = param_2 + 2;
  }
  else {
    pbVar4 = param_2 + 1;
    param_2 = (byte *)0x0;
  }
  bVar3 = (byte)param_2;
  if (bVar9) {
    bVar3 = 1;
  }
  pbVar1 = (byte *)(param_1 + -1);
  do {
    pbVar1 = pbVar1 + 1;
    *pbVar1 = bVar3;
  } while (pbVar1 != (byte *)(param_1 + 0xff));
  if (uVar6 == 0) {
    pbVar2 = pbVar4 + -1;
  }
  else {
LAB_0802a8e8:
    do {
      uVar7 = uVar6;
      pbVar1 = pbVar4;
      *(byte *)(param_1 + uVar7) = bVar3 ^ 1;
      while( true ) {
        pbVar4 = pbVar1 + 1;
        uVar6 = (uint)*pbVar1;
        if (uVar6 != 0x2d) break;
        uVar8 = (uint)pbVar1[1];
        if ((uVar8 == 0x5d) || ((int)uVar8 < (int)uVar7)) goto LAB_0802a8e8;
        pbVar1 = pbVar1 + 2;
        uVar6 = uVar7;
        do {
          uVar6 = uVar6 + 1;
          *(byte *)(param_1 + uVar6) = bVar3 ^ 1;
        } while ((int)uVar6 < (int)uVar8);
        iVar5 = (uVar8 - uVar7) + -1;
        if ((int)uVar8 <= (int)uVar7) {
          iVar5 = 0;
        }
        uVar7 = uVar7 + 1 + iVar5;
      }
      pbVar2 = pbVar4;
    } while ((uVar6 != 0x5d) && (pbVar2 = pbVar1, uVar6 != 0));
  }
  return pbVar2;
}

