
void FUN_080190b6(int param_1,undefined4 param_2,byte *param_3,int param_4,undefined4 *param_5,
                 undefined4 *param_6)

{
  byte bVar1;
  undefined4 *puVar2;
  byte *pbVar3;
  int iVar4;
  uint uVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  bool bVar8;
  
  iVar4 = 0;
  uVar5 = 0;
  while( true ) {
    bVar1 = param_3[uVar5];
    pbVar3 = param_3 + uVar5;
    if (((int)param_6 - (int)param_5 >> 2 <= (int)(uint)bVar1) || ((char)bVar1 < '\x01')) break;
    param_6 = param_6 + -(uint)bVar1;
    if (uVar5 < param_4 - 1U) {
      uVar5 = uVar5 + 1;
    }
    else {
      iVar4 = iVar4 + 1;
    }
  }
  puVar7 = (undefined4 *)(param_1 + -4);
  for (puVar2 = param_5; puVar2 != param_6; puVar2 = puVar2 + 1) {
    puVar7 = puVar7 + 1;
    *puVar7 = *puVar2;
  }
  puVar7 = (undefined4 *)((param_1 - (int)param_5) + (int)param_6);
  while (bVar8 = iVar4 != 0, iVar4 = iVar4 + -1, bVar8) {
    *puVar7 = param_2;
    bVar1 = *pbVar3;
    puVar6 = param_6 + bVar1;
    puVar2 = puVar7;
    for (; param_6 != puVar6; param_6 = param_6 + 1) {
      puVar2 = puVar2 + 1;
      *puVar2 = *param_6;
    }
    puVar7 = puVar7 + bVar1 + 1;
  }
  while (pbVar3 != param_3) {
    *puVar7 = param_2;
    pbVar3 = pbVar3 + -1;
    bVar1 = *pbVar3;
    puVar6 = param_6 + bVar1;
    puVar2 = puVar7;
    for (; param_6 != puVar6; param_6 = param_6 + 1) {
      puVar2 = puVar2 + 1;
      *puVar2 = *param_6;
    }
    puVar7 = puVar7 + bVar1 + 1;
  }
  return;
}

