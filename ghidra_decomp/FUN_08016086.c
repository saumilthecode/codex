
undefined4 *
FUN_08016086(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,int param_7,uint *param_8,int param_9)

{
  uint *puVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 local_70;
  undefined4 uStack_6c;
  undefined4 local_68;
  undefined4 uStack_64;
  undefined4 local_60;
  int local_5c;
  undefined1 auStack_58 [28];
  undefined1 auStack_3c [28];
  
  puVar1 = param_8;
  iVar3 = param_7;
  local_68 = param_3;
  uStack_64 = param_4;
  uVar2 = FUN_0801146c(param_7 + 0x6c);
  FUN_0801102c(uVar2,auStack_58);
  FUN_0801100c(uVar2,auStack_3c);
  local_5c = 0;
  FUN_080132fe(&local_70,param_2,local_68,uStack_64,param_5,param_6,&local_60,auStack_58,7,iVar3,
               &local_5c);
  local_68 = local_70;
  uStack_64 = uStack_6c;
  if (local_5c == 0) {
    *(undefined4 *)(param_9 + 0x18) = local_60;
  }
  else {
    *puVar1 = *puVar1 | 4;
  }
  iVar3 = FUN_08012eba(&local_68,&param_5);
  if (iVar3 != 0) {
    *puVar1 = *puVar1 | 2;
  }
  *param_1 = local_68;
  param_1[1] = uStack_64;
  return param_1;
}

