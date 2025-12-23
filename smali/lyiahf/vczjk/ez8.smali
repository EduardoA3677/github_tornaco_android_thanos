.class public final Llyiahf/vczjk/ez8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/qj8;

.field public final synthetic OooOOO0:J

.field public final synthetic OooOOOO:Llyiahf/vczjk/di6;

.field public final synthetic OooOOOo:Llyiahf/vczjk/yn4;

.field public final synthetic OooOOo0:Llyiahf/vczjk/a91;


# direct methods
.method public constructor <init>(JLlyiahf/vczjk/qj8;Llyiahf/vczjk/di6;Llyiahf/vczjk/yn4;Llyiahf/vczjk/a91;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-wide p1, p0, Llyiahf/vczjk/ez8;->OooOOO0:J

    iput-object p3, p0, Llyiahf/vczjk/ez8;->OooOOO:Llyiahf/vczjk/qj8;

    iput-object p4, p0, Llyiahf/vczjk/ez8;->OooOOOO:Llyiahf/vczjk/di6;

    iput-object p5, p0, Llyiahf/vczjk/ez8;->OooOOOo:Llyiahf/vczjk/yn4;

    iput-object p6, p0, Llyiahf/vczjk/ez8;->OooOOo0:Llyiahf/vczjk/a91;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 v0, p2, 0x3

    const/4 v1, 0x2

    const/4 v2, 0x1

    if-eq v0, v1, :cond_0

    move v0, v2

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    and-int/2addr p2, v2

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/zf1;

    invoke-virtual {v5, p2, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p1

    if-eqz p1, :cond_1

    sget-object p1, Llyiahf/vczjk/q6a;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v5, p1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/n6a;

    iget-object v3, p1, Llyiahf/vczjk/n6a;->OooOOO0:Llyiahf/vczjk/rn9;

    new-instance v6, Llyiahf/vczjk/hq;

    iget-object v11, p0, Llyiahf/vczjk/ez8;->OooOOo0:Llyiahf/vczjk/a91;

    iget-object v8, p0, Llyiahf/vczjk/ez8;->OooOOO:Llyiahf/vczjk/qj8;

    iget-object v9, p0, Llyiahf/vczjk/ez8;->OooOOOO:Llyiahf/vczjk/di6;

    iget-object v10, p0, Llyiahf/vczjk/ez8;->OooOOOo:Llyiahf/vczjk/yn4;

    const/16 v7, 0xb

    invoke-direct/range {v6 .. v11}, Llyiahf/vczjk/hq;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/a91;)V

    const p1, 0x2fd12ed0

    invoke-static {p1, v6, v5}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v4

    const/16 v6, 0x180

    iget-wide v1, p0, Llyiahf/vczjk/ez8;->OooOOO0:J

    invoke-static/range {v1 .. v6}, Llyiahf/vczjk/tp6;->OooO0Oo(JLlyiahf/vczjk/rn9;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    goto :goto_1

    :cond_1
    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
