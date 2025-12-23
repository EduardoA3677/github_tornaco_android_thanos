.class public final Llyiahf/vczjk/i4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/a91;

.field public final synthetic OooOOO0:Llyiahf/vczjk/ze3;

.field public final synthetic OooOOOO:Llyiahf/vczjk/qj8;

.field public final synthetic OooOOOo:J

.field public final synthetic OooOOo:J

.field public final synthetic OooOOo0:F

.field public final synthetic OooOOoo:J

.field public final synthetic OooOo0:Llyiahf/vczjk/a91;

.field public final synthetic OooOo00:J

.field public final synthetic OooOo0O:Llyiahf/vczjk/a91;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ze3;Llyiahf/vczjk/a91;Llyiahf/vczjk/qj8;JFJJJLlyiahf/vczjk/a91;Llyiahf/vczjk/a91;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/i4;->OooOOO0:Llyiahf/vczjk/ze3;

    iput-object p2, p0, Llyiahf/vczjk/i4;->OooOOO:Llyiahf/vczjk/a91;

    iput-object p3, p0, Llyiahf/vczjk/i4;->OooOOOO:Llyiahf/vczjk/qj8;

    iput-wide p4, p0, Llyiahf/vczjk/i4;->OooOOOo:J

    iput p6, p0, Llyiahf/vczjk/i4;->OooOOo0:F

    iput-wide p7, p0, Llyiahf/vczjk/i4;->OooOOo:J

    iput-wide p9, p0, Llyiahf/vczjk/i4;->OooOOoo:J

    iput-wide p11, p0, Llyiahf/vczjk/i4;->OooOo00:J

    iput-object p13, p0, Llyiahf/vczjk/i4;->OooOo0:Llyiahf/vczjk/a91;

    iput-object p14, p0, Llyiahf/vczjk/i4;->OooOo0O:Llyiahf/vczjk/a91;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 22

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

    if-eq v3, v4, :cond_0

    move v3, v5

    goto :goto_0

    :cond_0
    const/4 v3, 0x0

    :goto_0
    and-int/2addr v2, v5

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v2, v3}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v2

    if-eqz v2, :cond_1

    new-instance v2, Llyiahf/vczjk/h4;

    iget-object v3, v0, Llyiahf/vczjk/i4;->OooOo0O:Llyiahf/vczjk/a91;

    iget-object v4, v0, Llyiahf/vczjk/i4;->OooOo0:Llyiahf/vczjk/a91;

    const/4 v5, 0x1

    const/4 v6, 0x0

    invoke-direct {v2, v4, v3, v5, v6}, Llyiahf/vczjk/h4;-><init>(Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;IZ)V

    const v3, 0x51830875

    invoke-static {v3, v2, v1}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v4

    sget-object v2, Llyiahf/vczjk/bb2;->OooO00o:Llyiahf/vczjk/y21;

    invoke-static {v2, v1}, Llyiahf/vczjk/z21;->OooO0o0(Llyiahf/vczjk/y21;Llyiahf/vczjk/rf1;)J

    move-result-wide v12

    iget-wide v14, v0, Llyiahf/vczjk/i4;->OooOOo:J

    iget-wide v2, v0, Llyiahf/vczjk/i4;->OooOOoo:J

    iget-object v6, v0, Llyiahf/vczjk/i4;->OooOOO0:Llyiahf/vczjk/ze3;

    iget-object v7, v0, Llyiahf/vczjk/i4;->OooOOO:Llyiahf/vczjk/a91;

    iget-object v8, v0, Llyiahf/vczjk/i4;->OooOOOO:Llyiahf/vczjk/qj8;

    iget-wide v9, v0, Llyiahf/vczjk/i4;->OooOOOo:J

    iget v11, v0, Llyiahf/vczjk/i4;->OooOOo0:F

    move-object/from16 v16, v6

    iget-wide v5, v0, Llyiahf/vczjk/i4;->OooOo00:J

    const/16 v21, 0x6

    move-object/from16 v20, v1

    move-wide/from16 v18, v5

    move-object/from16 v6, v16

    const/4 v5, 0x0

    move-wide/from16 v16, v2

    invoke-static/range {v4 .. v21}, Llyiahf/vczjk/j4;->OooO00o(Llyiahf/vczjk/a91;Llyiahf/vczjk/hl5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/a91;Llyiahf/vczjk/qj8;JFJJJJLlyiahf/vczjk/rf1;I)V

    goto :goto_1

    :cond_1
    move-object/from16 v20, v1

    invoke-virtual/range {v20 .. v20}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_1
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
