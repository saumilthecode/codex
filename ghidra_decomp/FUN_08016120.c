
undefined4 *
FUN_08016120(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,int param_7,uint *param_8,int param_9)

{
  uint *puVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 local_98;
  undefined4 uStack_94;
  undefined4 local_90;
  undefined4 uStack_8c;
  undefined4 local_88;
  int local_84;
  undefined1 auStack_80 [48];
  undefined1 auStack_50 [48];
  
  puVar1 = param_8;
  iVar3 = param_7;
  local_90 = param_3;
  uStack_8c = param_4;
  uVar2 = FUN_0801146c(param_7 + 0x6c);
  FUN_0801108a(uVar2,auStack_80);
  FUN_0801104c(uVar2,auStack_50);
  local_84 = 0;
  FUN_080132fe(&local_98,param_2,local_90,uStack_8c,param_5,param_6,&local_88,auStack_80,0xc,iVar3,
               &local_84);
  local_90 = local_98;
  uStack_8c = uStack_94;
  if (local_84 == 0) {
    *(undefined4 *)(param_9 + 0x10) = local_88;
  }
  else {
    *puVar1 = *puVar1 | 4;
  }
  iVar3 = FUN_08012eba(&local_90,&param_5);
  if (iVar3 != 0) {
    *puVar1 = *puVar1 | 2;
  }
  *param_1 = local_90;
  param_1[1] = uStack_8c;
  return param_1;
}

