.class public final Llyiahf/vczjk/qh5;
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

.field final synthetic $enabled:Z

.field final synthetic $this_Row:Llyiahf/vczjk/iw7;


# direct methods
.method public constructor <init>(ZLlyiahf/vczjk/bf3;)V
    .locals 1

    sget-object v0, Llyiahf/vczjk/jw7;->OooO00o:Llyiahf/vczjk/jw7;

    iput-boolean p1, p0, Llyiahf/vczjk/qh5;->$enabled:Z

    iput-object p2, p0, Llyiahf/vczjk/qh5;->$content:Llyiahf/vczjk/bf3;

    iput-object v0, p0, Llyiahf/vczjk/qh5;->$this_Row:Llyiahf/vczjk/iw7;

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

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-eq v0, v1, :cond_0

    move v0, v3

    goto :goto_0

    :cond_0
    move v0, v2

    :goto_0
    and-int/2addr p2, v3

    check-cast p1, Llyiahf/vczjk/zf1;

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p2

    if-eqz p2, :cond_5

    iget-boolean p2, p0, Llyiahf/vczjk/qh5;->$enabled:Z

    if-eqz p2, :cond_3

    const p2, -0xb232d2e

    invoke-virtual {p1, p2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object p2, Llyiahf/vczjk/lm1;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/n21;

    iget-wide v0, p2, Llyiahf/vczjk/n21;->OooO00o:J

    sget-object p2, Llyiahf/vczjk/m31;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/k31;

    invoke-virtual {p2}, Llyiahf/vczjk/k31;->OooO0Oo()Z

    move-result p2

    const-wide/high16 v3, 0x3fe0000000000000L    # 0.5

    if-eqz p2, :cond_1

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooooOO(J)F

    move-result p2

    float-to-double v0, p2

    cmpl-double p2, v0, v3

    if-lez p2, :cond_2

    goto :goto_1

    :cond_1
    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooooOO(J)F

    move-result p2

    float-to-double v0, p2

    cmpg-double p2, v0, v3

    if-gez p2, :cond_2

    :goto_1
    const/high16 p2, 0x3f800000    # 1.0f

    goto :goto_2

    :cond_2
    const p2, 0x3f5eb852    # 0.87f

    :goto_2
    invoke-virtual {p1, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_4

    :cond_3
    const p2, -0xb232a4a

    invoke-virtual {p1, p2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object p2, Llyiahf/vczjk/lm1;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/n21;

    iget-wide v0, p2, Llyiahf/vczjk/n21;->OooO00o:J

    sget-object p2, Llyiahf/vczjk/m31;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/k31;

    invoke-virtual {p2}, Llyiahf/vczjk/k31;->OooO0Oo()Z

    move-result p2

    if-eqz p2, :cond_4

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooooOO(J)F

    goto :goto_3

    :cond_4
    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooooOO(J)F

    :goto_3
    invoke-virtual {p1, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const p2, 0x3ec28f5c    # 0.38f

    :goto_4
    sget-object v0, Llyiahf/vczjk/gm1;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-static {p2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object p2

    invoke-virtual {v0, p2}, Llyiahf/vczjk/jh1;->OooO00o(Ljava/lang/Object;)Llyiahf/vczjk/ke7;

    move-result-object p2

    new-instance v0, Llyiahf/vczjk/ph5;

    iget-object v1, p0, Llyiahf/vczjk/qh5;->$content:Llyiahf/vczjk/bf3;

    iget-object v2, p0, Llyiahf/vczjk/qh5;->$this_Row:Llyiahf/vczjk/iw7;

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/ph5;-><init>(Llyiahf/vczjk/bf3;Llyiahf/vczjk/iw7;)V

    const v1, -0x65af6da8

    invoke-static {v1, v0, p1}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v0

    const/16 v1, 0x38

    invoke-static {p2, v0, p1, v1}, Llyiahf/vczjk/r02;->OooO00o(Llyiahf/vczjk/ke7;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    goto :goto_5

    :cond_5
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_5
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
