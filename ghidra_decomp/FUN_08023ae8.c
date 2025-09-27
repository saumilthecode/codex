
undefined4 *
FUN_08023ae8(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,int param_7,uint *param_8,int param_9)

{
  uint *puVar1;
  int iVar2;
  int iVar3;
  undefined4 local_70;
  undefined4 uStack_6c;
  undefined4 local_68;
  undefined4 uStack_64;
  undefined4 local_60;
  int local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  
  puVar1 = param_8;
  iVar3 = param_7;
  local_68 = param_3;
  uStack_64 = param_4;
  iVar2 = FUN_0801146c(param_7 + 0x6c);
  iVar2 = *(int *)(iVar2 + 8);
  local_58 = *(undefined4 *)(iVar2 + 0x48);
  local_54 = *(undefined4 *)(iVar2 + 0x4c);
  local_50 = *(undefined4 *)(iVar2 + 0x50);
  local_4c = *(undefined4 *)(iVar2 + 0x54);
  local_48 = *(undefined4 *)(iVar2 + 0x58);
  local_44 = *(undefined4 *)(iVar2 + 0x5c);
  local_40 = *(undefined4 *)(iVar2 + 0x60);
  local_3c = *(undefined4 *)(iVar2 + 0x2c);
  local_38 = *(undefined4 *)(iVar2 + 0x30);
  local_34 = *(undefined4 *)(iVar2 + 0x34);
  local_30 = *(undefined4 *)(iVar2 + 0x38);
  local_2c = *(undefined4 *)(iVar2 + 0x3c);
  local_28 = *(undefined4 *)(iVar2 + 0x40);
  local_24 = *(undefined4 *)(iVar2 + 0x44);
  local_5c = 0;
  FUN_08022bf6(&local_70,param_2,local_68,uStack_64,param_5,param_6,&local_60,&local_58,7,iVar3,
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

