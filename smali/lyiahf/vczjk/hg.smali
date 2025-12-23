.class public final Llyiahf/vczjk/hg;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $iconVisible:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field

.field final synthetic $isLeft:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/le3;Z)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/hg;->$iconVisible:Llyiahf/vczjk/le3;

    iput-boolean p2, p0, Llyiahf/vczjk/hg;->$isLeft:Z

    const/4 p1, 0x3

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    check-cast p1, Llyiahf/vczjk/kl5;

    check-cast p2, Llyiahf/vczjk/rf1;

    check-cast p3, Ljava/lang/Number;

    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    check-cast p2, Llyiahf/vczjk/zf1;

    const p3, -0xbba9706

    invoke-virtual {p2, p3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object p3, Llyiahf/vczjk/jn9;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-virtual {p2, p3}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object p3

    check-cast p3, Llyiahf/vczjk/in9;

    iget-wide v0, p3, Llyiahf/vczjk/in9;->OooO00o:J

    invoke-virtual {p2, v0, v1}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result p3

    iget-object v2, p0, Llyiahf/vczjk/hg;->$iconVisible:Llyiahf/vczjk/le3;

    invoke-virtual {p2, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    or-int/2addr p3, v2

    iget-boolean v2, p0, Llyiahf/vczjk/hg;->$isLeft:Z

    invoke-virtual {p2, v2}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v2

    or-int/2addr p3, v2

    iget-object v2, p0, Llyiahf/vczjk/hg;->$iconVisible:Llyiahf/vczjk/le3;

    iget-boolean v3, p0, Llyiahf/vczjk/hg;->$isLeft:Z

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez p3, :cond_0

    sget-object p3, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v4, p3, :cond_1

    :cond_0
    new-instance v4, Llyiahf/vczjk/gg;

    invoke-direct {v4, v0, v1, v2, v3}, Llyiahf/vczjk/gg;-><init>(JLlyiahf/vczjk/le3;Z)V

    invoke-virtual {p2, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1
    check-cast v4, Llyiahf/vczjk/oe3;

    invoke-static {p1, v4}, Landroidx/compose/ui/draw/OooO00o;->OooO0O0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object p1

    const/4 p3, 0x0

    invoke-virtual {p2, p3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-object p1
.end method
