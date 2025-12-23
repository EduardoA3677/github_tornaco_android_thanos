.class public final Llyiahf/vczjk/dj9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/ei9;

.field public final synthetic OooOOO0:Llyiahf/vczjk/kl5;

.field public final synthetic OooOOOO:Ljava/lang/String;

.field public final synthetic OooOOOo:Llyiahf/vczjk/oe3;

.field public final synthetic OooOOo:Llyiahf/vczjk/rn9;

.field public final synthetic OooOOo0:Z

.field public final synthetic OooOOoo:Llyiahf/vczjk/nj4;

.field public final synthetic OooOo:Llyiahf/vczjk/rr5;

.field public final synthetic OooOo0:I

.field public final synthetic OooOo00:Llyiahf/vczjk/mj4;

.field public final synthetic OooOo0O:I

.field public final synthetic OooOo0o:Llyiahf/vczjk/ml9;

.field public final synthetic OooOoO:Llyiahf/vczjk/a91;

.field public final synthetic OooOoO0:Llyiahf/vczjk/a91;

.field public final synthetic OooOoOO:Llyiahf/vczjk/a91;

.field public final synthetic OooOoo0:Llyiahf/vczjk/qj8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kl5;Llyiahf/vczjk/ei9;Ljava/lang/String;Llyiahf/vczjk/oe3;ZLlyiahf/vczjk/rn9;Llyiahf/vczjk/nj4;Llyiahf/vczjk/mj4;IILlyiahf/vczjk/ml9;Llyiahf/vczjk/rr5;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/qj8;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/dj9;->OooOOO0:Llyiahf/vczjk/kl5;

    iput-object p2, p0, Llyiahf/vczjk/dj9;->OooOOO:Llyiahf/vczjk/ei9;

    iput-object p3, p0, Llyiahf/vczjk/dj9;->OooOOOO:Ljava/lang/String;

    iput-object p4, p0, Llyiahf/vczjk/dj9;->OooOOOo:Llyiahf/vczjk/oe3;

    iput-boolean p5, p0, Llyiahf/vczjk/dj9;->OooOOo0:Z

    iput-object p6, p0, Llyiahf/vczjk/dj9;->OooOOo:Llyiahf/vczjk/rn9;

    iput-object p7, p0, Llyiahf/vczjk/dj9;->OooOOoo:Llyiahf/vczjk/nj4;

    iput-object p8, p0, Llyiahf/vczjk/dj9;->OooOo00:Llyiahf/vczjk/mj4;

    iput p9, p0, Llyiahf/vczjk/dj9;->OooOo0:I

    iput p10, p0, Llyiahf/vczjk/dj9;->OooOo0O:I

    iput-object p11, p0, Llyiahf/vczjk/dj9;->OooOo0o:Llyiahf/vczjk/ml9;

    iput-object p12, p0, Llyiahf/vczjk/dj9;->OooOo:Llyiahf/vczjk/rr5;

    iput-object p13, p0, Llyiahf/vczjk/dj9;->OooOoO0:Llyiahf/vczjk/a91;

    iput-object p14, p0, Llyiahf/vczjk/dj9;->OooOoO:Llyiahf/vczjk/a91;

    iput-object p15, p0, Llyiahf/vczjk/dj9;->OooOoOO:Llyiahf/vczjk/a91;

    move-object/from16 p1, p16

    iput-object p1, p0, Llyiahf/vczjk/dj9;->OooOoo0:Llyiahf/vczjk/qj8;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 24

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

    sget v2, Landroidx/compose/ui/R$string;->default_error_message:I

    invoke-static {v2, v1}, Llyiahf/vczjk/ru6;->OooOo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    sget v2, Llyiahf/vczjk/wi9;->OooO00o:F

    sget v2, Llyiahf/vczjk/li9;->OooO0OO:F

    sget v3, Llyiahf/vczjk/li9;->OooO0O0:F

    iget-object v4, v0, Llyiahf/vczjk/dj9;->OooOOO0:Llyiahf/vczjk/kl5;

    invoke-static {v4, v2, v3}, Landroidx/compose/foundation/layout/OooO0OO;->OooO00o(Llyiahf/vczjk/kl5;FF)Llyiahf/vczjk/kl5;

    move-result-object v6

    new-instance v2, Llyiahf/vczjk/gx8;

    iget-object v3, v0, Llyiahf/vczjk/dj9;->OooOOO:Llyiahf/vczjk/ei9;

    iget-wide v4, v3, Llyiahf/vczjk/ei9;->OooO:J

    invoke-direct {v2, v4, v5}, Llyiahf/vczjk/gx8;-><init>(J)V

    new-instance v7, Llyiahf/vczjk/cj9;

    iget-object v15, v0, Llyiahf/vczjk/dj9;->OooOoo0:Llyiahf/vczjk/qj8;

    iget-object v4, v0, Llyiahf/vczjk/dj9;->OooOOOO:Ljava/lang/String;

    iget-boolean v9, v0, Llyiahf/vczjk/dj9;->OooOOo0:Z

    iget-object v10, v0, Llyiahf/vczjk/dj9;->OooOo0o:Llyiahf/vczjk/ml9;

    iget-object v11, v0, Llyiahf/vczjk/dj9;->OooOo:Llyiahf/vczjk/rr5;

    iget-object v12, v0, Llyiahf/vczjk/dj9;->OooOoO0:Llyiahf/vczjk/a91;

    iget-object v13, v0, Llyiahf/vczjk/dj9;->OooOoO:Llyiahf/vczjk/a91;

    iget-object v14, v0, Llyiahf/vczjk/dj9;->OooOoOO:Llyiahf/vczjk/a91;

    move-object/from16 v16, v3

    move-object v8, v4

    invoke-direct/range {v7 .. v16}, Llyiahf/vczjk/cj9;-><init>(Ljava/lang/String;ZLlyiahf/vczjk/ml9;Llyiahf/vczjk/rr5;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/qj8;Llyiahf/vczjk/ei9;)V

    move-object v15, v10

    move-object/from16 v17, v11

    const v3, 0x568400e5

    invoke-static {v3, v7, v1}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v19

    move v7, v9

    iget-object v9, v0, Llyiahf/vczjk/dj9;->OooOOo:Llyiahf/vczjk/rn9;

    const/high16 v22, 0x30000

    const/16 v23, 0x1000

    iget-object v5, v0, Llyiahf/vczjk/dj9;->OooOOOo:Llyiahf/vczjk/oe3;

    const/4 v8, 0x0

    iget-object v10, v0, Llyiahf/vczjk/dj9;->OooOOoo:Llyiahf/vczjk/nj4;

    iget-object v11, v0, Llyiahf/vczjk/dj9;->OooOo00:Llyiahf/vczjk/mj4;

    const/4 v12, 0x0

    iget v13, v0, Llyiahf/vczjk/dj9;->OooOo0:I

    iget v14, v0, Llyiahf/vczjk/dj9;->OooOo0O:I

    const/16 v16, 0x0

    const/16 v21, 0x0

    move-object/from16 v20, v1

    move-object/from16 v18, v2

    invoke-static/range {v4 .. v23}, Llyiahf/vczjk/w90;->OooO00o(Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/kl5;ZZLlyiahf/vczjk/rn9;Llyiahf/vczjk/nj4;Llyiahf/vczjk/mj4;ZIILlyiahf/vczjk/jka;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rr5;Llyiahf/vczjk/ri0;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;III)V

    goto :goto_1

    :cond_1
    move-object/from16 v20, v1

    invoke-virtual/range {v20 .. v20}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_1
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
