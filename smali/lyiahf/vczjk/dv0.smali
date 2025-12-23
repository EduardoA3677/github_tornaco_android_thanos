.class public abstract Llyiahf/vczjk/dv0;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    const/4 v0, 0x2

    int-to-float v0, v0

    sput v0, Llyiahf/vczjk/dv0;->OooO00o:F

    return-void
.end method

.method public static OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/cv0;
    .locals 27

    sget-object v0, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    move-object/from16 v1, p0

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/x21;

    iget-object v1, v0, Llyiahf/vczjk/x21;->OooooO0:Llyiahf/vczjk/cv0;

    if-nez v1, :cond_0

    new-instance v2, Llyiahf/vczjk/cv0;

    sget-object v1, Llyiahf/vczjk/kv0;->OooO0OO:Llyiahf/vczjk/y21;

    invoke-static {v0, v1}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v3

    sget-wide v5, Llyiahf/vczjk/n21;->OooO:J

    sget-object v1, Llyiahf/vczjk/kv0;->OooO00o:Llyiahf/vczjk/y21;

    invoke-static {v0, v1}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v7

    sget-object v9, Llyiahf/vczjk/kv0;->OooO0O0:Llyiahf/vczjk/y21;

    invoke-static {v0, v9}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v10

    const v12, 0x3ec28f5c    # 0.38f

    invoke-static {v12, v10, v11}, Llyiahf/vczjk/n21;->OooO0O0(FJ)J

    move-result-wide v10

    invoke-static {v0, v9}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v13

    invoke-static {v12, v13, v14}, Llyiahf/vczjk/n21;->OooO0O0(FJ)J

    move-result-wide v15

    invoke-static {v0, v1}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v17

    sget-object v1, Llyiahf/vczjk/kv0;->OooO0o:Llyiahf/vczjk/y21;

    invoke-static {v0, v1}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v19

    invoke-static {v0, v9}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v13

    invoke-static {v12, v13, v14}, Llyiahf/vczjk/n21;->OooO0O0(FJ)J

    move-result-wide v21

    sget-object v1, Llyiahf/vczjk/kv0;->OooO0o0:Llyiahf/vczjk/y21;

    invoke-static {v0, v1}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v13

    invoke-static {v12, v13, v14}, Llyiahf/vczjk/n21;->OooO0O0(FJ)J

    move-result-wide v23

    invoke-static {v0, v9}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v13

    invoke-static {v12, v13, v14}, Llyiahf/vczjk/n21;->OooO0O0(FJ)J

    move-result-wide v25

    move-wide v11, v10

    move-wide v9, v5

    move-wide v13, v5

    invoke-direct/range {v2 .. v26}, Llyiahf/vczjk/cv0;-><init>(JJJJJJJJJJJJ)V

    iput-object v2, v0, Llyiahf/vczjk/x21;->OooooO0:Llyiahf/vczjk/cv0;

    return-object v2

    :cond_0
    return-object v1
.end method
