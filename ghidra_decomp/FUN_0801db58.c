
undefined4 *
FUN_0801db58(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,int param_7,uint *param_8,undefined4 param_9)

{
  uint *puVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  undefined4 local_48;
  undefined4 uStack_44;
  undefined4 local_40;
  undefined4 uStack_3c;
  undefined4 local_34;
  undefined4 uStack_30;
  undefined4 local_2c;
  
  uVar2 = param_9;
  puVar1 = param_8;
  iVar4 = param_7;
  local_40 = param_3;
  uStack_3c = param_4;
  iVar3 = FUN_080190a8(param_7 + 0x6c);
  local_34 = 0;
  uStack_30 = 0;
  local_2c = 0;
  FUN_0801adf4(&local_48,param_2,local_40,uStack_3c,param_5,param_6,iVar4,puVar1,uVar2,
               *(undefined4 *)(*(int *)(iVar3 + 8) + 8),&local_34);
  local_40 = local_48;
  uStack_3c = uStack_44;
  FUN_0801fbe0(&local_34,uVar2);
  iVar4 = FUN_0800e0d6(&local_40,&param_5);
  if (iVar4 != 0) {
    *puVar1 = *puVar1 | 2;
  }
  *param_1 = local_40;
  param_1[1] = uStack_3c;
  return param_1;
}

