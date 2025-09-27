
bool FUN_0801fe7c(byte *param_1,int param_2,undefined4 *param_3)

{
  byte *pbVar1;
  byte bVar2;
  uint uVar3;
  byte *pbVar4;
  uint uVar5;
  byte *pbVar6;
  bool bVar7;
  
  pbVar4 = (byte *)*param_3;
  uVar5 = param_3[1] - 1;
  uVar3 = param_2 - 1U;
  if (uVar5 <= param_2 - 1U) {
    uVar3 = uVar5;
  }
  bVar7 = true;
  pbVar6 = param_1;
  while ((pbVar6 != param_1 + uVar3 && (bVar7 != false))) {
    pbVar1 = pbVar4 + uVar5;
    uVar5 = uVar5 - 1;
    bVar7 = *pbVar1 == *pbVar6;
    pbVar6 = pbVar6 + 1;
  }
  bVar2 = param_1[uVar3];
  pbVar6 = pbVar4 + uVar5;
  while ((pbVar6 != pbVar4 && (bVar7 != false))) {
    bVar7 = *pbVar6 == bVar2;
    pbVar6 = pbVar6 + -1;
  }
  if (('\0' < (char)bVar2) && (bVar2 < *pbVar4)) {
    bVar7 = false;
  }
  return bVar7;
}

