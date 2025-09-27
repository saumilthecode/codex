
undefined4 *
FUN_08023baa(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,int param_7,uint *param_8,int param_9)

{
  uint *puVar1;
  int iVar2;
  int iVar3;
  undefined4 local_98;
  undefined4 uStack_94;
  undefined4 local_90;
  undefined4 uStack_8c;
  undefined4 local_88;
  int local_84;
  undefined4 local_80;
  undefined4 local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
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
  local_90 = param_3;
  uStack_8c = param_4;
  iVar2 = FUN_0801146c(param_7 + 0x6c);
  iVar2 = *(int *)(iVar2 + 8);
  local_80 = *(undefined4 *)(iVar2 + 0x94);
  local_7c = *(undefined4 *)(iVar2 + 0x98);
  local_78 = *(undefined4 *)(iVar2 + 0x9c);
  local_74 = *(undefined4 *)(iVar2 + 0xa0);
  local_70 = *(undefined4 *)(iVar2 + 0xa4);
  local_6c = *(undefined4 *)(iVar2 + 0xa8);
  local_68 = *(undefined4 *)(iVar2 + 0xac);
  local_64 = *(undefined4 *)(iVar2 + 0xb0);
  local_60 = *(undefined4 *)(iVar2 + 0xb4);
  local_5c = *(undefined4 *)(iVar2 + 0xb8);
  local_58 = *(undefined4 *)(iVar2 + 0xbc);
  local_54 = *(undefined4 *)(iVar2 + 0xc0);
  local_50 = *(undefined4 *)(iVar2 + 100);
  local_4c = *(undefined4 *)(iVar2 + 0x68);
  local_48 = *(undefined4 *)(iVar2 + 0x6c);
  local_44 = *(undefined4 *)(iVar2 + 0x70);
  local_40 = *(undefined4 *)(iVar2 + 0x74);
  local_3c = *(undefined4 *)(iVar2 + 0x78);
  local_38 = *(undefined4 *)(iVar2 + 0x7c);
  local_34 = *(undefined4 *)(iVar2 + 0x80);
  local_30 = *(undefined4 *)(iVar2 + 0x84);
  local_2c = *(undefined4 *)(iVar2 + 0x88);
  local_28 = *(undefined4 *)(iVar2 + 0x8c);
  local_24 = *(undefined4 *)(iVar2 + 0x90);
  local_84 = 0;
  FUN_08022bf6(&local_98,param_2,local_90,uStack_8c,param_5,param_6,&local_88,&local_80,0xc,iVar3,
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

