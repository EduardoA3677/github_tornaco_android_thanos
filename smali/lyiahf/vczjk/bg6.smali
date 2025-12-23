.class public final Llyiahf/vczjk/bg6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field public final synthetic OooOOO:Z

.field public final synthetic OooOOO0:Ljava/lang/String;

.field public final synthetic OooOOOO:Llyiahf/vczjk/ml9;

.field public final synthetic OooOOOo:Llyiahf/vczjk/rr5;

.field public final synthetic OooOOo:Llyiahf/vczjk/a91;

.field public final synthetic OooOOo0:Z

.field public final synthetic OooOOoo:Llyiahf/vczjk/a91;

.field public final synthetic OooOo0:Llyiahf/vczjk/qj8;

.field public final synthetic OooOo00:Llyiahf/vczjk/ei9;


# direct methods
.method public constructor <init>(Ljava/lang/String;ZLlyiahf/vczjk/ml9;Llyiahf/vczjk/rr5;ZLlyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/ei9;Llyiahf/vczjk/qj8;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/bg6;->OooOOO0:Ljava/lang/String;

    iput-boolean p2, p0, Llyiahf/vczjk/bg6;->OooOOO:Z

    iput-object p3, p0, Llyiahf/vczjk/bg6;->OooOOOO:Llyiahf/vczjk/ml9;

    iput-object p4, p0, Llyiahf/vczjk/bg6;->OooOOOo:Llyiahf/vczjk/rr5;

    iput-boolean p5, p0, Llyiahf/vczjk/bg6;->OooOOo0:Z

    iput-object p6, p0, Llyiahf/vczjk/bg6;->OooOOo:Llyiahf/vczjk/a91;

    iput-object p7, p0, Llyiahf/vczjk/bg6;->OooOOoo:Llyiahf/vczjk/a91;

    iput-object p8, p0, Llyiahf/vczjk/bg6;->OooOo00:Llyiahf/vczjk/ei9;

    iput-object p9, p0, Llyiahf/vczjk/bg6;->OooOo0:Llyiahf/vczjk/qj8;

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    move-object/from16 v0, p0

    move-object/from16 v3, p1

    check-cast v3, Llyiahf/vczjk/ze3;

    move-object/from16 v1, p2

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p3

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v4, v2, 0x6

    if-nez v4, :cond_1

    move-object v4, v1

    check-cast v4, Llyiahf/vczjk/zf1;

    invoke-virtual {v4, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_0

    const/4 v4, 0x4

    goto :goto_0

    :cond_0
    const/4 v4, 0x2

    :goto_0
    or-int/2addr v2, v4

    :cond_1
    and-int/lit8 v4, v2, 0x13

    const/16 v5, 0x12

    if-eq v4, v5, :cond_2

    const/4 v4, 0x1

    goto :goto_1

    :cond_2
    const/4 v4, 0x0

    :goto_1
    and-int/lit8 v5, v2, 0x1

    move-object v13, v1

    check-cast v13, Llyiahf/vczjk/zf1;

    invoke-virtual {v13, v5, v4}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v1

    if-eqz v1, :cond_3

    sget-object v1, Llyiahf/vczjk/xf6;->OooO00o:Llyiahf/vczjk/xf6;

    new-instance v4, Llyiahf/vczjk/gx5;

    iget-object v8, v0, Llyiahf/vczjk/bg6;->OooOo00:Llyiahf/vczjk/ei9;

    iget-object v9, v0, Llyiahf/vczjk/bg6;->OooOo0:Llyiahf/vczjk/qj8;

    iget-boolean v5, v0, Llyiahf/vczjk/bg6;->OooOOO:Z

    iget-boolean v6, v0, Llyiahf/vczjk/bg6;->OooOOo0:Z

    iget-object v7, v0, Llyiahf/vczjk/bg6;->OooOOOo:Llyiahf/vczjk/rr5;

    invoke-direct/range {v4 .. v9}, Llyiahf/vczjk/gx5;-><init>(ZZLlyiahf/vczjk/rr5;Llyiahf/vczjk/ei9;Llyiahf/vczjk/qj8;)V

    const v9, -0x27281f48

    invoke-static {v9, v4, v13}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v12

    shl-int/lit8 v2, v2, 0x3

    and-int/lit8 v14, v2, 0x70

    move-object v10, v8

    iget-object v8, v0, Llyiahf/vczjk/bg6;->OooOOo:Llyiahf/vczjk/a91;

    iget-object v9, v0, Llyiahf/vczjk/bg6;->OooOOoo:Llyiahf/vczjk/a91;

    iget-object v2, v0, Llyiahf/vczjk/bg6;->OooOOO0:Ljava/lang/String;

    move v4, v5

    iget-object v5, v0, Llyiahf/vczjk/bg6;->OooOOOO:Llyiahf/vczjk/ml9;

    const/4 v11, 0x0

    move-object v15, v7

    move v7, v6

    move-object v6, v15

    invoke-virtual/range {v1 .. v14}, Llyiahf/vczjk/xf6;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/ze3;ZLlyiahf/vczjk/ml9;Llyiahf/vczjk/n24;ZLlyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/ei9;Llyiahf/vczjk/di6;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    goto :goto_2

    :cond_3
    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_2
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
