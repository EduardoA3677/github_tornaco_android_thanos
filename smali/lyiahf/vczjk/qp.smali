.class public final Llyiahf/vczjk/qp;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $content:Llyiahf/vczjk/bf3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bf3;"
        }
    .end annotation
.end field

.field final synthetic $contentPadding:Llyiahf/vczjk/bi6;

.field final synthetic $windowInsets:Llyiahf/vczjk/kna;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kna;Llyiahf/vczjk/bi6;Llyiahf/vczjk/bf3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/qp;->$windowInsets:Llyiahf/vczjk/kna;

    iput-object p2, p0, Llyiahf/vczjk/qp;->$contentPadding:Llyiahf/vczjk/bi6;

    iput-object p3, p0, Llyiahf/vczjk/qp;->$content:Llyiahf/vczjk/bf3;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

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

    check-cast p1, Llyiahf/vczjk/zf1;

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p2

    if-eqz p2, :cond_3

    sget-object p2, Llyiahf/vczjk/gm1;->OooO00o:Llyiahf/vczjk/jh1;

    sget-object v0, Llyiahf/vczjk/lm1;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/n21;

    iget-wide v0, v0, Llyiahf/vczjk/n21;->OooO00o:J

    sget-object v2, Llyiahf/vczjk/m31;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {p1, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/k31;

    invoke-virtual {v2}, Llyiahf/vczjk/k31;->OooO0Oo()Z

    move-result v2

    const-wide/high16 v3, 0x3fe0000000000000L    # 0.5

    if-eqz v2, :cond_1

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooooOO(J)F

    move-result v0

    float-to-double v0, v0

    cmpl-double v0, v0, v3

    if-lez v0, :cond_2

    goto :goto_1

    :cond_1
    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooooOO(J)F

    move-result v0

    float-to-double v0, v0

    cmpg-double v0, v0, v3

    if-gez v0, :cond_2

    :goto_1
    const v0, 0x3f3d70a4    # 0.74f

    goto :goto_2

    :cond_2
    const v0, 0x3f19999a    # 0.6f

    :goto_2
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v0

    invoke-virtual {p2, v0}, Llyiahf/vczjk/jh1;->OooO00o(Ljava/lang/Object;)Llyiahf/vczjk/ke7;

    move-result-object p2

    new-instance v0, Llyiahf/vczjk/pp;

    iget-object v1, p0, Llyiahf/vczjk/qp;->$windowInsets:Llyiahf/vczjk/kna;

    iget-object v2, p0, Llyiahf/vczjk/qp;->$contentPadding:Llyiahf/vczjk/bi6;

    iget-object v3, p0, Llyiahf/vczjk/qp;->$content:Llyiahf/vczjk/bf3;

    invoke-direct {v0, v1, v2, v3}, Llyiahf/vczjk/pp;-><init>(Llyiahf/vczjk/kna;Llyiahf/vczjk/bi6;Llyiahf/vczjk/bf3;)V

    const v1, 0x23c83d5a

    invoke-static {v1, v0, p1}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v0

    const/16 v1, 0x38

    invoke-static {p2, v0, p1, v1}, Llyiahf/vczjk/r02;->OooO00o(Llyiahf/vczjk/ke7;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    goto :goto_3

    :cond_3
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
