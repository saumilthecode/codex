
undefined4
FUN_0800dd04(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            char param_5,int param_6,int param_7,undefined4 param_8,undefined4 param_9,
            undefined4 param_10)

{
  int iVar1;
  undefined4 uVar2;
  undefined1 *puVar3;
  int *piVar4;
  undefined4 local_a8 [4];
  undefined1 auStack_98 [68];
  int local_54;
  undefined4 local_50;
  undefined4 uStack_4c;
  undefined1 auStack_44 [4];
  undefined1 *local_40 [2];
  undefined1 auStack_38 [20];
  
  local_50 = param_3;
  uStack_4c = param_4;
  FUN_0800890c(auStack_44,param_6 + 0x6c);
  uVar2 = FUN_08018e8c(auStack_44);
  piVar4 = local_a8;
  local_40[0] = (undefined1 *)FUN_08008940();
  puVar3 = auStack_98;
  local_a8[2] = param_9;
  local_a8[3] = param_10;
  local_a8[0] = 0;
  local_54 = FUN_0800d708(local_40,puVar3,0x40,DAT_0800ddf4);
  if (0x3f < local_54) {
    iVar1 = -(local_54 + 8U & 0xfffffff8);
    piVar4 = (int *)((int)local_a8 + iVar1);
    local_54 = local_54 + 1;
    local_40[0] = (undefined1 *)FUN_08008940();
    puVar3 = auStack_98 + iVar1;
    *(undefined4 *)((int)local_a8 + iVar1 + 8) = param_9;
    *(undefined4 *)(auStack_98 + iVar1 + -4) = param_10;
    *(undefined4 *)((int)local_a8 + iVar1) = 0;
    local_54 = FUN_0800d708(local_40,puVar3,local_54,DAT_0800ddf4);
  }
  local_40[0] = auStack_38;
  FUN_0801ea7c(local_40,local_54,0);
  FUN_0800d670(uVar2,puVar3,puVar3 + local_54,local_40[0]);
  piVar4[2] = (int)local_40;
  piVar4[1] = param_7;
  *piVar4 = param_6;
  if (param_5 == '\0') {
    FUN_0800daac(param_1,param_2,local_50,uStack_4c);
  }
  else {
    FUN_0800d854();
  }
  FUN_0801e9cc(local_40);
  FUN_080089f4(auStack_44);
  return param_1;
}

