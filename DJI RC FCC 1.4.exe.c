#include "DJI RC FCC 1.4.exe.h"



// WARNING: Removing unreachable block (ram,0x000140446944)

void entry(void)

{
  FUN_140446990(0);
  return;
}



void FUN_140446952(uint param_1)

{
  undefined4 uVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined uVar4;
  ulonglong unaff_RBP;
  undefined4 *unaff_RDI;
  
  puVar3 = (undefined4 *)((longlong)unaff_RDI + unaff_RBP);
  uVar4 = *(undefined *)puVar3;
  if ((5 < param_1) && (unaff_RBP < 0xfffffffffffffffd)) {
    uVar2 = param_1 - 4;
    do {
      param_1 = uVar2;
      uVar1 = *puVar3;
      puVar3 = puVar3 + 1;
      *unaff_RDI = uVar1;
      unaff_RDI = unaff_RDI + 1;
      uVar2 = param_1 - 4;
    } while (3 < param_1);
    uVar4 = *(undefined *)puVar3;
    if (param_1 == 0) {
      return;
    }
  }
  do {
    puVar3 = (undefined4 *)((longlong)puVar3 + 1);
    *(undefined *)unaff_RDI = uVar4;
    param_1 = param_1 - 1;
    uVar4 = *(undefined *)puVar3;
    unaff_RDI = (undefined4 *)((longlong)unaff_RDI + 1);
  } while (param_1 != 0);
  return;
}



// WARNING: Control flow encountered bad instruction data

void FUN_140446990(ulonglong param_1)

{
  LPVOID lpAddress;
  byte *pbVar1;
  char cVar2;
  char cVar3;
  ushort uVar4;
  uint uVar5;
  ulonglong uVar6;
  int iVar7;
  uint uVar8;
  HMODULE hModule;
  FARPROC pFVar9;
  ulonglong uVar10;
  int iVar11;
  uint *puVar12;
  HMODULE pHVar13;
  uint unaff_EBX;
  FARPROC *ppFVar14;
  ulonglong *puVar15;
  undefined *puVar16;
  ulonglong unaff_RBP;
  uint *unaff_RSI;
  byte *unaff_RDI;
  uint *puVar18;
  uint *puVar19;
  uint *puVar20;
  byte bVar21;
  bool bVar22;
  byte bVar23;
  code *unaff_retaddr;
  ulonglong local_res8 [4];
  undefined local_50 [48];
  undefined8 uStack_20;
  undefined *puVar17;
  
  do {
    while( true ) {
      bVar23 = *(byte *)unaff_RSI;
      bVar21 = CARRY4(unaff_EBX,unaff_EBX);
      unaff_EBX = unaff_EBX * 2;
      if (unaff_EBX == 0) {
        uVar8 = *unaff_RSI;
        bVar22 = unaff_RSI < (uint *)0xfffffffffffffffc;
        unaff_RSI = unaff_RSI + 1;
        bVar21 = CARRY4(uVar8,uVar8) || CARRY4(uVar8 * 2,(uint)bVar22);
        unaff_EBX = uVar8 * 2 + (uint)bVar22;
        bVar23 = *(byte *)unaff_RSI;
      }
      uVar10 = (ulonglong)bVar23;
      if (!(bool)bVar21) break;
      unaff_RSI = (uint *)((longlong)unaff_RSI + 1);
      *unaff_RDI = bVar23;
      unaff_RDI = unaff_RDI + 1;
    }
    while( true ) {
      iVar7 = (*unaff_retaddr)();
      uVar6 = local_res8[0];
      iVar11 = (int)param_1;
      uVar8 = iVar7 * 2 + (uint)bVar21;
      bVar23 = CARRY4(unaff_EBX,unaff_EBX);
      unaff_EBX = unaff_EBX * 2;
      if (unaff_EBX == 0) {
        uVar5 = *unaff_RSI;
        bVar22 = unaff_RSI < (uint *)0xfffffffffffffffc;
        unaff_RSI = unaff_RSI + 1;
        bVar23 = CARRY4(uVar5,uVar5) || CARRY4(uVar5 * 2,(uint)bVar22);
        unaff_EBX = uVar5 * 2 + (uint)bVar22;
        uVar10 = (ulonglong)*(byte *)unaff_RSI;
      }
      if ((bool)bVar23) break;
      uVar8 = (*unaff_retaddr)();
      bVar21 = CARRY4(uVar8,uVar8) || CARRY4(uVar8 * 2,(uint)bVar23);
    }
    if (uVar8 < 3) {
      bVar23 = CARRY4(unaff_EBX,unaff_EBX);
      unaff_EBX = unaff_EBX * 2;
      if (unaff_EBX == 0) {
        uVar8 = *unaff_RSI;
        bVar22 = unaff_RSI < (uint *)0xfffffffffffffffc;
        unaff_RSI = unaff_RSI + 1;
        bVar23 = CARRY4(uVar8,uVar8) || CARRY4(uVar8 * 2,(uint)bVar22);
        unaff_EBX = uVar8 * 2 + (uint)bVar22;
      }
      if (!(bool)bVar23) goto LAB_1404469fc;
LAB_140446a24:
      (*unaff_retaddr)();
      iVar11 = iVar11 * 2 + (uint)bVar23;
    }
    else {
      unaff_RSI = (uint *)((longlong)unaff_RSI + 1);
      uVar8 = ((uVar8 - 3) * 0x100 | (uint)uVar10 & 0xff) ^ 0xffffffff;
      if (uVar8 == 0) {
        puVar18 = (uint *)(local_res8[0] + 0x43e000);
        do {
          if (*puVar18 == 0) {
            puVar15 = (ulonglong *)(local_res8[0] - 4);
            puVar18 = puVar18 + 1;
            while( true ) {
              bVar23 = *(byte *)puVar18;
              puVar20 = (uint *)((longlong)puVar18 + 1);
              uVar10 = (ulonglong)(uint)bVar23;
              if (bVar23 == 0) break;
              if (0xef < bVar23) {
                uVar4 = *(ushort *)puVar20;
                puVar20 = (uint *)((longlong)puVar18 + 3);
                uVar10 = (ulonglong)(CONCAT12(bVar23,uVar4) & 0xff0fffff);
                if ((CONCAT12(bVar23,uVar4) & 0xfffff) == 0) {
                  uVar10 = (ulonglong)*puVar20;
                  puVar20 = (uint *)((longlong)puVar18 + 7);
                }
              }
              puVar15 = (ulonglong *)((longlong)puVar15 + uVar10);
              uVar10 = *puVar15;
              *puVar15 = (uVar10 >> 0x38 | (uVar10 & 0xff000000000000) >> 0x28 |
                          (uVar10 & 0xff0000000000) >> 0x18 | (uVar10 & 0xff00000000) >> 8 |
                          (uVar10 & 0xff000000) << 8 | (uVar10 & 0xff0000) << 0x18 |
                          (uVar10 & 0xff00) << 0x28 | uVar10 << 0x38) + local_res8[0];
              puVar18 = puVar20;
            }
            lpAddress = (LPVOID)(local_res8[0] - 0x1000);
            uStack_20 = 0x140446b12;
            local_res8[0] = uVar10;
            VirtualProtect(lpAddress,0x1000,4,(PDWORD)local_res8);
            pbVar1 = (byte *)(uVar6 - 0xda1);
            *pbVar1 = *pbVar1 & 0x7f;
            pbVar1 = (byte *)(uVar6 - 0xd79);
            *pbVar1 = *pbVar1 & 0x7f;
            uStack_20 = 0x140446b30;
            VirtualProtect(lpAddress,0x1000,(DWORD)local_res8[0],(PDWORD)local_res8);
            puVar16 = &stack0x00000030;
            do {
              puVar17 = puVar16 + -8;
              *(undefined8 *)(puVar16 + -8) = 0;
              puVar16 = puVar16 + -8;
            } while (puVar17 != local_50);
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          ppFVar14 = (FARPROC *)(puVar18[1] + local_res8[0]);
          puVar20 = puVar18 + 2;
          uStack_20 = 0x140446a67;
          hModule = LoadLibraryA((LPCSTR)((ulonglong)*puVar18 + 0x446350 + local_res8[0]));
          while( true ) {
            cVar3 = *(char *)puVar20;
            puVar18 = (uint *)((longlong)puVar20 + 1);
            if (cVar3 == '\0') break;
            if (cVar3 < '\0') {
              puVar18 = (uint *)(ulonglong)*(ushort *)puVar18;
              puVar20 = (uint *)((longlong)puVar20 + 3);
            }
            else {
              puVar12 = puVar18;
              puVar19 = puVar18;
              do {
                puVar20 = puVar19;
                if (puVar12 == (uint *)0x0) break;
                puVar12 = (uint *)((longlong)puVar12 + -1);
                puVar20 = (uint *)((longlong)puVar19 + 1);
                cVar2 = *(char *)puVar19;
                puVar19 = puVar20;
              } while ((char)(cVar3 + -1) != cVar2);
            }
            uStack_20 = 0x140446a91;
            pHVar13 = hModule;
            pFVar9 = GetProcAddress(hModule,(LPCSTR)puVar18);
            if (pFVar9 == (FARPROC)0x0) {
                    // WARNING: Could not recover jumptable at 0x000140446a9f. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
              ExitProcess((UINT)pHVar13);
              return;
            }
            *ppFVar14 = pFVar9;
            ppFVar14 = ppFVar14 + 1;
          }
        } while( true );
      }
      bVar23 = (uVar8 & 1) != 0;
      unaff_RBP = (ulonglong)((int)uVar8 >> 1);
      if ((bool)bVar23) goto LAB_140446a24;
LAB_1404469fc:
      iVar11 = iVar11 + 1;
      bVar23 = CARRY4(unaff_EBX,unaff_EBX);
      unaff_EBX = unaff_EBX * 2;
      if (unaff_EBX == 0) {
        uVar8 = *unaff_RSI;
        bVar22 = unaff_RSI < (uint *)0xfffffffffffffffc;
        unaff_RSI = unaff_RSI + 1;
        bVar23 = CARRY4(uVar8,uVar8) || CARRY4(uVar8 * 2,(uint)bVar22);
        unaff_EBX = uVar8 * 2 + (uint)bVar22;
      }
      if ((bool)bVar23) goto LAB_140446a24;
      do {
        (*unaff_retaddr)();
        iVar11 = iVar11 * 2 + (uint)bVar23;
        bVar23 = CARRY4(unaff_EBX,unaff_EBX);
        unaff_EBX = unaff_EBX * 2;
        if (unaff_EBX == 0) {
          uVar8 = *unaff_RSI;
          bVar22 = unaff_RSI < (uint *)0xfffffffffffffffc;
          unaff_RSI = unaff_RSI + 1;
          bVar23 = CARRY4(uVar8,uVar8) || CARRY4(uVar8 * 2,(uint)bVar22);
          unaff_EBX = uVar8 * 2 + (uint)bVar22;
        }
      } while (!(bool)bVar23);
      iVar11 = iVar11 + 2;
    }
    uVar8 = iVar11 + 2 + (uint)(unaff_RBP < 0xfffffffffffffb00);
    param_1 = (ulonglong)uVar8;
    FUN_140446952(uVar8);
  } while( true );
}


