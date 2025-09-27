
void FUN_08001c10(int param_1,uint param_2,uint param_3)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 local_28;
  undefined4 uStack_24;
  undefined4 local_20;
  undefined4 uStack_1c;
  int local_18;
  
  uVar2 = DAT_08001cac;
  iVar1 = DAT_08001ca4;
  if (param_1 == 0) {
    *(uint *)(DAT_08001ca4 + 0x30) = *(uint *)(DAT_08001ca4 + 0x30) | 1;
    local_28 = 0x100;
    uStack_24 = 2;
    local_20 = 0;
    uStack_1c = 3;
    local_18 = param_1;
    FUN_080011c0(DAT_08001ca8,&local_28,0,*(uint *)(iVar1 + 0x30) & 1);
    *(uint *)(iVar1 + 8) = *(uint *)(iVar1 + 8) & 0xf89fffff | param_2 | param_3;
    return;
  }
  *(uint *)(DAT_08001ca4 + 0x30) = *(uint *)(DAT_08001ca4 + 0x30) | 4;
  local_18 = 0;
  local_28 = 0x200;
  uStack_24 = 2;
  local_20 = 0;
  uStack_1c = 3;
  FUN_080011c0(uVar2,&local_28,0,*(uint *)(iVar1 + 0x30) & 4);
  *(uint *)(iVar1 + 8) = *(uint *)(iVar1 + 8) & 0x7ffffff | param_2 | param_3 << 3;
  return;
}

