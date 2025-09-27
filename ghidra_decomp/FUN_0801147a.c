
void FUN_0801147a(int param_1,undefined1 param_2,byte *param_3,int param_4,undefined1 *param_5,
                 undefined1 *param_6)

{
  byte bVar1;
  byte *pbVar2;
  int iVar3;
  uint uVar4;
  undefined1 *puVar5;
  undefined1 *puVar6;
  undefined1 *puVar7;
  bool bVar8;
  
  iVar3 = 0;
  uVar4 = 0;
  while( true ) {
    bVar1 = param_3[uVar4];
    pbVar2 = param_3 + uVar4;
    if (((int)param_6 - (int)param_5 <= (int)(uint)bVar1) || ((char)bVar1 < '\x01')) break;
    param_6 = param_6 + -(uint)bVar1;
    if (uVar4 < param_4 - 1U) {
      uVar4 = uVar4 + 1;
    }
    else {
      iVar3 = iVar3 + 1;
    }
  }
  puVar7 = (undefined1 *)(param_1 + -1);
  for (puVar5 = param_5; puVar5 != param_6; puVar5 = puVar5 + 1) {
    puVar7 = puVar7 + 1;
    *puVar7 = *puVar5;
  }
  puVar7 = param_6 + (param_1 - (int)param_5);
  while (bVar8 = iVar3 != 0, iVar3 = iVar3 + -1, bVar8) {
    *puVar7 = param_2;
    bVar1 = *pbVar2;
    puVar6 = param_6 + bVar1;
    puVar5 = puVar7;
    for (; param_6 != puVar6; param_6 = param_6 + 1) {
      puVar5 = puVar5 + 1;
      *puVar5 = *param_6;
    }
    puVar7 = puVar7 + bVar1 + 1;
  }
  while (pbVar2 != param_3) {
    *puVar7 = param_2;
    pbVar2 = pbVar2 + -1;
    bVar1 = *pbVar2;
    puVar6 = param_6 + bVar1;
    puVar5 = puVar7;
    for (; param_6 != puVar6; param_6 = param_6 + 1) {
      puVar5 = puVar5 + 1;
      *puVar5 = *param_6;
    }
    puVar7 = puVar7 + bVar1 + 1;
  }
  return;
}

