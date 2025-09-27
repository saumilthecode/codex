
int FUN_0802a92c(undefined1 *param_1,int param_2,undefined4 param_3)

{
  int iVar1;
  undefined4 *puVar2;
  undefined1 *local_80 [2];
  int local_78;
  undefined2 local_74;
  undefined2 local_72;
  undefined1 *local_70;
  int local_6c;
  undefined4 local_1c;
  
  puVar2 = (undefined4 *)*DAT_0802a994;
  if (param_2 < 0) {
    *puVar2 = 0x8b;
    iVar1 = -1;
  }
  else {
    local_74 = 0x208;
    local_1c = 0;
    if (param_2 == 0) {
      local_78 = 0;
    }
    else {
      local_78 = param_2 + -1;
    }
    local_72 = 0xffff;
    local_80[0] = param_1;
    local_70 = param_1;
    local_6c = local_78;
    iVar1 = FUN_08029c80(puVar2,local_80,param_3);
    if (iVar1 + 1 < 0 != SCARRY4(iVar1,1)) {
      *puVar2 = 0x8b;
    }
    if (param_2 != 0) {
      *local_80[0] = 0;
    }
  }
  return iVar1;
}

