
undefined4 *
FUN_080143dc(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined4 param_7,uint *param_8,
            undefined4 param_9)

{
  uint *puVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 local_38;
  undefined4 uStack_34;
  undefined4 local_30;
  undefined4 uStack_2c;
  undefined4 local_28;
  undefined4 local_24 [2];
  
  puVar1 = param_8;
  local_28 = DAT_08014464;
  local_30 = param_3;
  uStack_2c = param_4;
  FUN_0800aa82(&local_28,0x20);
  FUN_08014014(&local_38,param_2,local_30,uStack_2c,param_5,param_6,param_7,puVar1,&local_28);
  uVar2 = local_28;
  local_30 = local_38;
  uStack_2c = uStack_34;
  local_24[0] = FUN_08008940();
  FUN_0801f588(uVar2,param_9,puVar1,local_24);
  iVar3 = FUN_08012eba(&local_30,&param_5);
  if (iVar3 != 0) {
    *puVar1 = *puVar1 | 2;
  }
  *param_1 = local_30;
  param_1[1] = uStack_2c;
  FUN_08010c74(local_28);
  return param_1;
}

