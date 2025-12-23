.class public final Llyiahf/vczjk/k08;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/qs5;

.field public final synthetic OooOOO0:Llyiahf/vczjk/qs5;

.field public final synthetic OooOOOO:Llyiahf/vczjk/xr1;

.field public final synthetic OooOOOo:Llyiahf/vczjk/lg0;

.field public final synthetic OooOOo:Llyiahf/vczjk/h48;

.field public final synthetic OooOOo0:Llyiahf/vczjk/hb8;

.field public final synthetic OooOOoo:Llyiahf/vczjk/qs5;

.field public final synthetic OooOo0:Landroid/content/Context;

.field public final synthetic OooOo00:Llyiahf/vczjk/wa5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/qs5;Llyiahf/vczjk/qs5;Llyiahf/vczjk/xr1;Llyiahf/vczjk/lg0;Llyiahf/vczjk/hb8;Llyiahf/vczjk/h48;Llyiahf/vczjk/qs5;Llyiahf/vczjk/wa5;Landroid/content/Context;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/k08;->OooOOO0:Llyiahf/vczjk/qs5;

    iput-object p2, p0, Llyiahf/vczjk/k08;->OooOOO:Llyiahf/vczjk/qs5;

    iput-object p3, p0, Llyiahf/vczjk/k08;->OooOOOO:Llyiahf/vczjk/xr1;

    iput-object p4, p0, Llyiahf/vczjk/k08;->OooOOOo:Llyiahf/vczjk/lg0;

    iput-object p5, p0, Llyiahf/vczjk/k08;->OooOOo0:Llyiahf/vczjk/hb8;

    iput-object p6, p0, Llyiahf/vczjk/k08;->OooOOo:Llyiahf/vczjk/h48;

    iput-object p7, p0, Llyiahf/vczjk/k08;->OooOOoo:Llyiahf/vczjk/qs5;

    iput-object p8, p0, Llyiahf/vczjk/k08;->OooOo00:Llyiahf/vczjk/wa5;

    iput-object p9, p0, Llyiahf/vczjk/k08;->OooOo0:Landroid/content/Context;

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/iw7;

    move-object/from16 v8, p2

    check-cast v8, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p3

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const-string v3, "$this$ThanoxBottomSheetScaffold"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v3, v2, 0x6

    if-nez v3, :cond_1

    move-object v3, v8

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_0

    const/4 v3, 0x4

    goto :goto_0

    :cond_0
    const/4 v3, 0x2

    :goto_0
    or-int/2addr v2, v3

    :cond_1
    and-int/lit8 v3, v2, 0x13

    const/16 v4, 0x12

    if-ne v3, v4, :cond_3

    move-object v3, v8

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v4

    if-nez v4, :cond_2

    goto :goto_1

    :cond_2
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_2

    :cond_3
    :goto_1
    iget-object v3, v0, Llyiahf/vczjk/k08;->OooOOO0:Llyiahf/vczjk/qs5;

    invoke-interface {v3}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/i28;

    iget-boolean v3, v3, Llyiahf/vczjk/i28;->OooO00o:Z

    xor-int/lit8 v3, v3, 0x1

    new-instance v9, Llyiahf/vczjk/i08;

    iget-object v14, v0, Llyiahf/vczjk/k08;->OooOOo:Llyiahf/vczjk/h48;

    iget-object v13, v0, Llyiahf/vczjk/k08;->OooOOo0:Llyiahf/vczjk/hb8;

    iget-object v4, v0, Llyiahf/vczjk/k08;->OooOo00:Llyiahf/vczjk/wa5;

    iget-object v5, v0, Llyiahf/vczjk/k08;->OooOo0:Landroid/content/Context;

    iget-object v10, v0, Llyiahf/vczjk/k08;->OooOOO:Llyiahf/vczjk/qs5;

    iget-object v11, v0, Llyiahf/vczjk/k08;->OooOOOO:Llyiahf/vczjk/xr1;

    iget-object v12, v0, Llyiahf/vczjk/k08;->OooOOOo:Llyiahf/vczjk/lg0;

    iget-object v15, v0, Llyiahf/vczjk/k08;->OooOOoo:Llyiahf/vczjk/qs5;

    move-object/from16 v16, v4

    move-object/from16 v17, v5

    invoke-direct/range {v9 .. v17}, Llyiahf/vczjk/i08;-><init>(Llyiahf/vczjk/qs5;Llyiahf/vczjk/xr1;Llyiahf/vczjk/lg0;Llyiahf/vczjk/hb8;Llyiahf/vczjk/h48;Llyiahf/vczjk/qs5;Llyiahf/vczjk/wa5;Landroid/content/Context;)V

    const v4, 0x1ce9ff95

    invoke-static {v4, v9, v8}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v7

    and-int/lit8 v2, v2, 0xe

    const/high16 v4, 0x180000

    or-int v9, v2, v4

    const/4 v4, 0x0

    const/16 v10, 0x1e

    move v2, v3

    const/4 v3, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    invoke-static/range {v1 .. v10}, Landroidx/compose/animation/OooO0O0;->OooO0OO(Llyiahf/vczjk/iw7;ZLlyiahf/vczjk/kl5;Llyiahf/vczjk/ep2;Llyiahf/vczjk/ct2;Ljava/lang/String;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    :goto_2
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
