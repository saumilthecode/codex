
undefined4
FUN_0802a228(undefined4 param_1,uint *param_2,uint *param_3,undefined4 param_4,code *param_5)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  uint uVar4;
  bool bVar5;
  
  uVar4 = param_2[4];
  if ((int)param_2[4] < (int)param_2[2]) {
    uVar4 = param_2[2];
  }
  *param_3 = uVar4;
  if (*(char *)((int)param_2 + 0x43) != '\0') {
    *param_3 = uVar4 + 1;
  }
  if ((int)(*param_2 << 0x1a) < 0) {
    *param_3 = *param_3 + 2;
  }
  uVar4 = *param_2 & 6;
  if (uVar4 == 0) {
    for (; (int)uVar4 < (int)(param_2[3] - *param_3); uVar4 = uVar4 + 1) {
      iVar1 = (*param_5)(param_1,param_4,(int)param_2 + 0x19,1);
      if (iVar1 == -1) goto LAB_0802a2cc;
    }
  }
  uVar3 = (uint)*(byte *)((int)param_2 + 0x43);
  if (uVar3 != 0) {
    uVar3 = 1;
  }
  if ((int)(*param_2 << 0x1a) < 0) {
    *(undefined1 *)((int)param_2 + uVar3 + 0x43) = 0x30;
    *(undefined1 *)((int)param_2 + uVar3 + 0x44) = *(undefined1 *)((int)param_2 + 0x45);
    uVar3 = uVar3 + 2;
  }
  iVar1 = (*param_5)(param_1,param_4,(int)param_2 + 0x43,uVar3);
  if (iVar1 == -1) {
LAB_0802a2cc:
    uVar2 = 0xffffffff;
  }
  else {
    bVar5 = (*param_2 & 6) == 4;
    if (bVar5) {
      uVar4 = param_2[3] - *param_3;
    }
    if (bVar5) {
      uVar4 = uVar4 & ~((int)uVar4 >> 0x1f);
    }
    else {
      uVar4 = 0;
    }
    if ((int)param_2[4] < (int)param_2[2]) {
      uVar4 = uVar4 + (param_2[2] - param_2[4]);
    }
    for (uVar3 = 0; uVar4 != uVar3; uVar3 = uVar3 + 1) {
      iVar1 = (*param_5)(param_1,param_4,(int)param_2 + 0x1a,1);
      if (iVar1 == -1) goto LAB_0802a2cc;
    }
    uVar2 = 0;
  }
  return uVar2;
}

