
void FUN_08017ce4(undefined4 param_1,uint *param_2,uint param_3)

{
  uint *puVar1;
  uint uVar2;
  uint uVar3;
  undefined8 uVar4;
  
  uVar4 = CONCAT44(param_2,param_1);
  uVar2 = *param_2;
  if (0x3fffffff < uVar2) {
    uVar4 = FUN_08010502(DAT_08017d1c);
  }
  puVar1 = (uint *)((ulonglong)uVar4 >> 0x20);
  if ((param_3 < uVar2) && (uVar3 = param_3 << 1, uVar2 < param_3 << 1)) {
    if (uVar3 < 0x40000000) {
      *puVar1 = uVar3;
      uVar2 = uVar3;
    }
    else {
      uVar2 = 0x3fffffff;
      *puVar1 = 0x3fffffff;
    }
  }
  FUN_08017cc6((int)uVar4,uVar2 + 1);
  return;
}

