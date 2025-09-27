
undefined4
FUN_08019a90(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            char param_5,int param_6,int param_7,undefined4 param_8,undefined4 param_9,
            undefined4 param_10)

{
  int iVar1;
  int iVar2;
  undefined1 *puVar3;
  int *piVar4;
  undefined4 local_98 [4];
  undefined1 auStack_88 [64];
  undefined1 *local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 uStack_3c;
  undefined1 auStack_34 [4];
  undefined1 auStack_30 [4];
  undefined4 local_2c [2];
  
  local_40 = param_3;
  uStack_3c = param_4;
  FUN_0800890c(auStack_30,param_6 + 0x6c);
  local_44 = FUN_08018e8c(auStack_30);
  piVar4 = local_98;
  local_2c[0] = FUN_08008940();
  puVar3 = auStack_88;
  local_98[2] = param_9;
  local_98[3] = param_10;
  local_98[0] = 0;
  iVar2 = FUN_0800d708(local_2c,puVar3,0x40,DAT_08019b88);
  if (0x3f < iVar2) {
    iVar1 = -(iVar2 + 8U & 0xfffffff8);
    piVar4 = (int *)((int)local_98 + iVar1);
    local_48 = (undefined1 *)(iVar2 + 1);
    local_2c[0] = FUN_08008940();
    puVar3 = auStack_88 + iVar1;
    *(undefined4 *)((int)local_98 + iVar1 + 8) = param_9;
    *(undefined4 *)(auStack_88 + iVar1 + -4) = param_10;
    *(undefined4 *)((int)local_98 + iVar1) = 0;
    iVar2 = FUN_0800d708(local_2c,puVar3,local_48,DAT_08019b88);
  }
  local_2c[0] = FUN_0800ae2c(iVar2,0,auStack_34);
  local_48 = puVar3 + iVar2;
  FUN_0800af44(local_2c);
  FUN_08018820(local_44,puVar3,local_48,local_2c[0]);
  piVar4[2] = (int)local_2c;
  piVar4[1] = param_7;
  *piVar4 = param_6;
  if (param_5 == '\0') {
    FUN_0801983c(param_1,param_2,local_40,uStack_3c);
  }
  else {
    FUN_080195e8();
  }
  FUN_08018900(local_2c[0]);
  FUN_080089f4(auStack_30);
  return param_1;
}

