
undefined4
FUN_08012ce4(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            byte param_5,int param_6,byte param_7,undefined4 param_8,undefined4 param_9,
            undefined4 param_10)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined1 *puVar4;
  int *piVar5;
  undefined4 local_a0 [4];
  undefined1 auStack_90 [68];
  undefined1 *local_4c;
  uint local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 uStack_3c;
  undefined1 auStack_34 [4];
  undefined1 auStack_30 [4];
  undefined4 local_2c [2];
  
  local_48 = (uint)param_5;
  local_40 = param_3;
  uStack_3c = param_4;
  FUN_0800890c(auStack_30,param_6 + 0x6c);
  local_44 = FUN_0801126c(auStack_30);
  piVar5 = local_a0;
  local_2c[0] = FUN_08008940();
  puVar4 = auStack_90;
  local_a0[2] = param_9;
  local_a0[3] = param_10;
  local_a0[0] = 0;
  iVar3 = FUN_0800d708(local_2c,puVar4,0x40,DAT_08012de8);
  if (0x3f < iVar3) {
    iVar1 = -(iVar3 + 8U & 0xfffffff8);
    piVar5 = (int *)((int)local_a0 + iVar1);
    local_4c = (undefined1 *)(iVar3 + 1);
    local_2c[0] = FUN_08008940();
    puVar4 = auStack_90 + iVar1;
    *(undefined4 *)((int)local_a0 + iVar1 + 8) = param_9;
    *(undefined4 *)(auStack_90 + iVar1 + -4) = param_10;
    *(undefined4 *)((int)local_a0 + iVar1) = 0;
    iVar3 = FUN_0800d708(local_2c,puVar4,local_4c,DAT_08012de8);
  }
  local_2c[0] = FUN_0800a7c4(iVar3,0,auStack_34);
  local_4c = puVar4 + iVar3;
  FUN_0800a904(local_2c);
  FUN_08010c84(local_44,puVar4,local_4c,local_2c[0]);
  uVar2 = local_48;
  piVar5[1] = (uint)param_7;
  piVar5[2] = (int)local_2c;
  if (uVar2 == 0) {
    *piVar5 = param_6;
    FUN_08012a7c(param_1,param_2,local_40,uStack_3c);
  }
  else {
    *piVar5 = param_6;
    FUN_08012814(param_1,param_2,local_40,uStack_3c);
  }
  FUN_08010c74(local_2c[0]);
  FUN_080089f4(auStack_30);
  return param_1;
}

