.class public final Llyiahf/vczjk/yf0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/a91;

.field public final synthetic OooOOO0:Llyiahf/vczjk/lg0;

.field public final synthetic OooOOOO:Llyiahf/vczjk/a91;

.field public final synthetic OooOOOo:F

.field public final synthetic OooOOo:Z

.field public final synthetic OooOOo0:F

.field public final synthetic OooOOoo:Llyiahf/vczjk/qj8;

.field public final synthetic OooOo:Llyiahf/vczjk/a91;

.field public final synthetic OooOo0:J

.field public final synthetic OooOo00:J

.field public final synthetic OooOo0O:F

.field public final synthetic OooOo0o:F

.field public final synthetic OooOoO:Llyiahf/vczjk/a91;

.field public final synthetic OooOoO0:Llyiahf/vczjk/a91;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/lg0;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;FFZLlyiahf/vczjk/qj8;JJFFLlyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/yf0;->OooOOO0:Llyiahf/vczjk/lg0;

    iput-object p2, p0, Llyiahf/vczjk/yf0;->OooOOO:Llyiahf/vczjk/a91;

    iput-object p3, p0, Llyiahf/vczjk/yf0;->OooOOOO:Llyiahf/vczjk/a91;

    iput p4, p0, Llyiahf/vczjk/yf0;->OooOOOo:F

    iput p5, p0, Llyiahf/vczjk/yf0;->OooOOo0:F

    iput-boolean p6, p0, Llyiahf/vczjk/yf0;->OooOOo:Z

    iput-object p7, p0, Llyiahf/vczjk/yf0;->OooOOoo:Llyiahf/vczjk/qj8;

    iput-wide p8, p0, Llyiahf/vczjk/yf0;->OooOo00:J

    iput-wide p10, p0, Llyiahf/vczjk/yf0;->OooOo0:J

    iput p12, p0, Llyiahf/vczjk/yf0;->OooOo0O:F

    iput p13, p0, Llyiahf/vczjk/yf0;->OooOo0o:F

    iput-object p14, p0, Llyiahf/vczjk/yf0;->OooOo:Llyiahf/vczjk/a91;

    iput-object p15, p0, Llyiahf/vczjk/yf0;->OooOoO0:Llyiahf/vczjk/a91;

    move-object/from16 p1, p16

    iput-object p1, p0, Llyiahf/vczjk/yf0;->OooOoO:Llyiahf/vczjk/a91;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 25

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

    move-object v10, v1

    check-cast v10, Llyiahf/vczjk/zf1;

    invoke-virtual {v10, v2, v3}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v1

    if-eqz v1, :cond_3

    iget-object v1, v0, Llyiahf/vczjk/yf0;->OooOOO0:Llyiahf/vczjk/lg0;

    iget-object v9, v1, Llyiahf/vczjk/lg0;->OooO00o:Llyiahf/vczjk/zl8;

    new-instance v2, Llyiahf/vczjk/wf0;

    iget-object v3, v0, Llyiahf/vczjk/yf0;->OooOOOO:Llyiahf/vczjk/a91;

    iget v4, v0, Llyiahf/vczjk/yf0;->OooOOOo:F

    invoke-direct {v2, v3, v4}, Llyiahf/vczjk/wf0;-><init>(Llyiahf/vczjk/a91;F)V

    const v3, -0x1ef8305a

    invoke-static {v3, v2, v10}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v5

    new-instance v11, Llyiahf/vczjk/xf0;

    iget-object v2, v0, Llyiahf/vczjk/yf0;->OooOoO0:Llyiahf/vczjk/a91;

    iget-object v12, v0, Llyiahf/vczjk/yf0;->OooOOO0:Llyiahf/vczjk/lg0;

    iget v13, v0, Llyiahf/vczjk/yf0;->OooOOOo:F

    iget v14, v0, Llyiahf/vczjk/yf0;->OooOOo0:F

    iget-boolean v15, v0, Llyiahf/vczjk/yf0;->OooOOo:Z

    iget-object v3, v0, Llyiahf/vczjk/yf0;->OooOOoo:Llyiahf/vczjk/qj8;

    iget-wide v6, v0, Llyiahf/vczjk/yf0;->OooOo00:J

    move-object/from16 v24, v2

    move-object/from16 v16, v3

    iget-wide v2, v0, Llyiahf/vczjk/yf0;->OooOo0:J

    iget v4, v0, Llyiahf/vczjk/yf0;->OooOo0O:F

    iget v8, v0, Llyiahf/vczjk/yf0;->OooOo0o:F

    move-wide/from16 v19, v2

    iget-object v2, v0, Llyiahf/vczjk/yf0;->OooOo:Llyiahf/vczjk/a91;

    move-object/from16 v23, v2

    move/from16 v21, v4

    move-wide/from16 v17, v6

    move/from16 v22, v8

    invoke-direct/range {v11 .. v24}, Llyiahf/vczjk/xf0;-><init>(Llyiahf/vczjk/lg0;FFZLlyiahf/vczjk/qj8;JJFFLlyiahf/vczjk/a91;Llyiahf/vczjk/a91;)V

    const v2, -0x309d717b

    invoke-static {v2, v11, v10}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v6

    new-instance v2, Llyiahf/vczjk/b6;

    iget-object v3, v0, Llyiahf/vczjk/yf0;->OooOoO:Llyiahf/vczjk/a91;

    const/4 v4, 0x6

    invoke-direct {v2, v4, v3, v1}, Llyiahf/vczjk/b6;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    const v3, -0x4242b29c

    invoke-static {v3, v2, v10}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v7

    invoke-virtual {v10, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v2, :cond_1

    sget-object v2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v3, v2, :cond_2

    :cond_1
    new-instance v3, Llyiahf/vczjk/k1;

    const/16 v2, 0x10

    invoke-direct {v3, v1, v2}, Llyiahf/vczjk/k1;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v10, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_2
    move-object v8, v3

    check-cast v8, Llyiahf/vczjk/le3;

    iget-object v4, v0, Llyiahf/vczjk/yf0;->OooOOO:Llyiahf/vczjk/a91;

    const/16 v11, 0xdb0

    invoke-static/range {v4 .. v11}, Llyiahf/vczjk/vc6;->OooO0O0(Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/zl8;Llyiahf/vczjk/rf1;I)V

    goto :goto_1

    :cond_3
    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_1
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
