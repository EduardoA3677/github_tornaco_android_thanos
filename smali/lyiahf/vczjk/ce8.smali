.class public final Llyiahf/vczjk/ce8;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $magnifierCenter:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field

.field final synthetic $platformMagnifier:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/oe3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ce8;->$magnifierCenter:Llyiahf/vczjk/le3;

    iput-object p2, p0, Llyiahf/vczjk/ce8;->$platformMagnifier:Llyiahf/vczjk/oe3;

    const/4 p1, 0x3

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    check-cast p1, Llyiahf/vczjk/kl5;

    check-cast p2, Llyiahf/vczjk/rf1;

    check-cast p3, Ljava/lang/Number;

    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    check-cast p2, Llyiahf/vczjk/zf1;

    const p1, 0x2d4acc1b

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p1, p0, Llyiahf/vczjk/ce8;->$magnifierCenter:Llyiahf/vczjk/le3;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object p3

    sget-object v0, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne p3, v0, :cond_0

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooO0Oo(Llyiahf/vczjk/le3;)Llyiahf/vczjk/w62;

    move-result-object p3

    invoke-virtual {p2, p3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_0
    check-cast p3, Llyiahf/vczjk/p29;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_1

    new-instance p1, Llyiahf/vczjk/gi;

    invoke-interface {p3}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/p86;

    iget-wide v1, v1, Llyiahf/vczjk/p86;->OooO00o:J

    new-instance v3, Llyiahf/vczjk/p86;

    invoke-direct {v3, v1, v2}, Llyiahf/vczjk/p86;-><init>(J)V

    sget-object v1, Llyiahf/vczjk/ge8;->OooO0O0:Llyiahf/vczjk/n1a;

    new-instance v2, Llyiahf/vczjk/p86;

    sget-wide v4, Llyiahf/vczjk/ge8;->OooO0OO:J

    invoke-direct {v2, v4, v5}, Llyiahf/vczjk/p86;-><init>(J)V

    const/16 v4, 0x8

    invoke-direct {p1, v3, v1, v2, v4}, Llyiahf/vczjk/gi;-><init>(Ljava/lang/Object;Llyiahf/vczjk/n1a;Ljava/lang/Object;I)V

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1
    check-cast p1, Llyiahf/vczjk/gi;

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v2, :cond_2

    if-ne v3, v0, :cond_3

    :cond_2
    new-instance v3, Llyiahf/vczjk/fe8;

    const/4 v2, 0x0

    invoke-direct {v3, p3, p1, v2}, Llyiahf/vczjk/fe8;-><init>(Llyiahf/vczjk/p29;Llyiahf/vczjk/gi;Llyiahf/vczjk/yo1;)V

    invoke-virtual {p2, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3
    check-cast v3, Llyiahf/vczjk/ze3;

    invoke-static {v1, p2, v3}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-object p1, p1, Llyiahf/vczjk/gi;->OooO0OO:Llyiahf/vczjk/xl;

    iget-object p3, p0, Llyiahf/vczjk/ce8;->$platformMagnifier:Llyiahf/vczjk/oe3;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-nez v1, :cond_4

    if-ne v2, v0, :cond_5

    :cond_4
    new-instance v2, Llyiahf/vczjk/be8;

    invoke-direct {v2, p1}, Llyiahf/vczjk/be8;-><init>(Llyiahf/vczjk/xl;)V

    invoke-virtual {p2, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    check-cast v2, Llyiahf/vczjk/le3;

    invoke-interface {p3, v2}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/kl5;

    const/4 p3, 0x0

    invoke-virtual {p2, p3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-object p1
.end method
