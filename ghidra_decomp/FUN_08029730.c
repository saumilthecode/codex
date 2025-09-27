
int FUN_08029730(uint param_1,uint param_2,uint param_3,uint param_4,int *param_5,int *param_6)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint local_20;
  uint local_1c;
  
  local_20 = param_1;
  local_1c = param_2;
  iVar1 = FUN_08028f6c(param_1,1);
  if (iVar1 == 0) {
    FUN_08028754(DAT_080297dc,0x30f,0,DAT_080297d8);
  }
  uVar6 = (param_4 << 1) >> 0x15;
  local_1c = param_4 & 0xfffff;
  if (uVar6 != 0) {
    local_1c = local_1c | 0x100000;
  }
  if (param_3 == 0) {
    iVar4 = FUN_0802918a(&local_1c);
    *(uint *)(iVar1 + 0x14) = local_1c;
    uVar2 = iVar4 + 0x20;
    iVar4 = 1;
  }
  else {
    local_20 = param_3;
    uVar2 = FUN_0802918a(&local_20);
    if (uVar2 == 0) {
      *(uint *)(iVar1 + 0x14) = local_20;
    }
    else {
      uVar5 = local_1c << (0x20 - uVar2 & 0xff);
      local_1c = local_1c >> (uVar2 & 0xff);
      *(uint *)(iVar1 + 0x14) = uVar5 | local_20;
    }
    *(uint *)(iVar1 + 0x18) = local_1c;
    if (local_1c == 0) {
      iVar4 = 1;
    }
    else {
      iVar4 = 2;
    }
  }
  *(int *)(iVar1 + 0x10) = iVar4;
  if (uVar6 == 0) {
    *param_5 = uVar2 - 0x432;
    iVar3 = FUN_0802914c(*(undefined4 *)(iVar1 + iVar4 * 4 + 0x10));
    iVar3 = iVar4 * 0x20 - iVar3;
  }
  else {
    *param_5 = (uVar6 - 0x433) + uVar2;
    iVar3 = 0x35 - uVar2;
  }
  *param_6 = iVar3;
  return iVar1;
}

