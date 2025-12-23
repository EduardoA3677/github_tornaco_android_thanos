.class public final Llyiahf/vczjk/cj9;
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

.field public final synthetic OooOOo0:Llyiahf/vczjk/a91;

.field public final synthetic OooOOoo:Llyiahf/vczjk/a91;

.field public final synthetic OooOo0:Llyiahf/vczjk/ei9;

.field public final synthetic OooOo00:Llyiahf/vczjk/qj8;


# direct methods
.method public constructor <init>(Ljava/lang/String;ZLlyiahf/vczjk/ml9;Llyiahf/vczjk/rr5;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/qj8;Llyiahf/vczjk/ei9;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/cj9;->OooOOO0:Ljava/lang/String;

    iput-boolean p2, p0, Llyiahf/vczjk/cj9;->OooOOO:Z

    iput-object p3, p0, Llyiahf/vczjk/cj9;->OooOOOO:Llyiahf/vczjk/ml9;

    iput-object p4, p0, Llyiahf/vczjk/cj9;->OooOOOo:Llyiahf/vczjk/rr5;

    iput-object p5, p0, Llyiahf/vczjk/cj9;->OooOOo0:Llyiahf/vczjk/a91;

    iput-object p6, p0, Llyiahf/vczjk/cj9;->OooOOo:Llyiahf/vczjk/a91;

    iput-object p7, p0, Llyiahf/vczjk/cj9;->OooOOoo:Llyiahf/vczjk/a91;

    iput-object p8, p0, Llyiahf/vczjk/cj9;->OooOo00:Llyiahf/vczjk/qj8;

    iput-object p9, p0, Llyiahf/vczjk/cj9;->OooOo0:Llyiahf/vczjk/ei9;

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

    move-object v14, v1

    check-cast v14, Llyiahf/vczjk/zf1;

    invoke-virtual {v14, v5, v4}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v1

    if-eqz v1, :cond_3

    sget-object v1, Llyiahf/vczjk/li9;->OooO00o:Llyiahf/vczjk/li9;

    shl-int/lit8 v2, v2, 0x3

    and-int/lit8 v15, v2, 0x70

    iget-object v11, v0, Llyiahf/vczjk/cj9;->OooOo0:Llyiahf/vczjk/ei9;

    iget-object v2, v0, Llyiahf/vczjk/cj9;->OooOOO0:Ljava/lang/String;

    iget-boolean v4, v0, Llyiahf/vczjk/cj9;->OooOOO:Z

    iget-object v5, v0, Llyiahf/vczjk/cj9;->OooOOOO:Llyiahf/vczjk/ml9;

    iget-object v6, v0, Llyiahf/vczjk/cj9;->OooOOOo:Llyiahf/vczjk/rr5;

    iget-object v7, v0, Llyiahf/vczjk/cj9;->OooOOo0:Llyiahf/vczjk/a91;

    iget-object v8, v0, Llyiahf/vczjk/cj9;->OooOOo:Llyiahf/vczjk/a91;

    iget-object v9, v0, Llyiahf/vczjk/cj9;->OooOOoo:Llyiahf/vczjk/a91;

    iget-object v10, v0, Llyiahf/vczjk/cj9;->OooOo00:Llyiahf/vczjk/qj8;

    const/4 v12, 0x0

    const/4 v13, 0x0

    invoke-virtual/range {v1 .. v15}, Llyiahf/vczjk/li9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/ze3;ZLlyiahf/vczjk/ml9;Llyiahf/vczjk/n24;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/qj8;Llyiahf/vczjk/ei9;Llyiahf/vczjk/di6;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    goto :goto_2

    :cond_3
    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_2
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
