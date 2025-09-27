
uint FUN_0802c270(undefined4 *param_1,uint param_2,undefined4 param_3)

{
  uint uVar1;
  undefined4 *puVar2;
  undefined4 *local_80 [2];
  uint local_78;
  undefined2 local_74;
  undefined2 local_72;
  undefined4 *local_70;
  uint local_6c;
  undefined4 local_1c;
  
  puVar2 = (undefined4 *)*DAT_0802c2e8;
  if (param_2 < 0x20000000) {
    local_74 = 0x208;
    local_1c = 0;
    local_80[0] = param_1;
    local_70 = param_1;
    if (param_2 == 0) {
      local_72 = 0xffff;
      local_78 = param_2;
      local_6c = param_2;
      FUN_0802c65c(puVar2,local_80,param_3);
    }
    else {
      local_78 = (param_2 - 1) * 4;
      local_72 = 0xffff;
      local_6c = local_78;
      uVar1 = FUN_0802c65c(puVar2,local_80,param_3);
      *local_80[0] = 0;
      if (uVar1 < param_2) {
        return uVar1;
      }
    }
  }
  *puVar2 = 0x8b;
  return 0xffffffff;
}

