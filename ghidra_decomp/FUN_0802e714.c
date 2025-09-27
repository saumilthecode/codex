
undefined8 FUN_0802e714(int param_1,uint param_2,int *param_3,undefined4 param_4)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  undefined8 uVar4;
  
  uVar1 = DAT_0802e774;
  uVar4 = CONCAT44(param_2,param_1);
  uVar2 = param_2 & 0x7fffffff;
  iVar3 = 0;
  *param_3 = 0;
  if ((uVar2 <= uVar1) && (uVar2 != 0 || param_1 != 0)) {
    if ((param_2 & DAT_0802e778) == 0) {
      uVar4 = FUN_08006228(param_1,param_2,0,DAT_0802e77c,param_4);
      iVar3 = -0x36;
      uVar2 = (uint)((ulonglong)uVar4 >> 0x20) & 0x7fffffff;
    }
    param_1 = (int)uVar4;
    param_2 = (uint)((ulonglong)uVar4 >> 0x20) & 0x800fffff | 0x3fe00000;
    *param_3 = ((int)uVar2 >> 0x14) + -0x3fe + iVar3;
  }
  return CONCAT44(param_2,param_1);
}

