.class public final Llyiahf/vczjk/iu8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/a91;

.field public final synthetic OooOOO0:Llyiahf/vczjk/a91;

.field public final synthetic OooOOOO:Llyiahf/vczjk/a91;

.field public final synthetic OooOOOo:Llyiahf/vczjk/rn9;

.field public final synthetic OooOOo:J

.field public final synthetic OooOOo0:J


# direct methods
.method public constructor <init>(Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/rn9;JJ)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/iu8;->OooOOO0:Llyiahf/vczjk/a91;

    iput-object p2, p0, Llyiahf/vczjk/iu8;->OooOOO:Llyiahf/vczjk/a91;

    iput-object p3, p0, Llyiahf/vczjk/iu8;->OooOOOO:Llyiahf/vczjk/a91;

    iput-object p4, p0, Llyiahf/vczjk/iu8;->OooOOOo:Llyiahf/vczjk/rn9;

    iput-wide p5, p0, Llyiahf/vczjk/iu8;->OooOOo0:J

    iput-wide p7, p0, Llyiahf/vczjk/iu8;->OooOOo:J

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v3, v2, 0x3

    const/4 v4, 0x2

    const/4 v5, 0x1

    const/4 v6, 0x0

    if-eq v3, v4, :cond_0

    move v3, v5

    goto :goto_0

    :cond_0
    move v3, v6

    :goto_0
    and-int/2addr v2, v5

    move-object v15, v1

    check-cast v15, Llyiahf/vczjk/zf1;

    invoke-virtual {v15, v2, v3}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v1

    if-eqz v1, :cond_1

    const v1, -0xa1260e1

    invoke-virtual {v15, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v7, v0, Llyiahf/vczjk/iu8;->OooOOO:Llyiahf/vczjk/a91;

    iget-object v10, v0, Llyiahf/vczjk/iu8;->OooOOOo:Llyiahf/vczjk/rn9;

    iget-wide v11, v0, Llyiahf/vczjk/iu8;->OooOOo0:J

    iget-object v8, v0, Llyiahf/vczjk/iu8;->OooOOO0:Llyiahf/vczjk/a91;

    iget-object v9, v0, Llyiahf/vczjk/iu8;->OooOOOO:Llyiahf/vczjk/a91;

    iget-wide v13, v0, Llyiahf/vczjk/iu8;->OooOOo:J

    const/16 v16, 0x0

    invoke-static/range {v7 .. v16}, Llyiahf/vczjk/lu8;->OooO00o(Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/rn9;JJLlyiahf/vczjk/rf1;I)V

    invoke-virtual {v15, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_1

    :cond_1
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_1
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
