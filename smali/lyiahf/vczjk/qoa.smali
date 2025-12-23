.class public final Llyiahf/vczjk/qoa;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $insets:Llyiahf/vczjk/kna;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/s13;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/qoa;->$insets:Llyiahf/vczjk/kna;

    const/4 p1, 0x3

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/kl5;

    check-cast p2, Llyiahf/vczjk/rf1;

    check-cast p3, Ljava/lang/Number;

    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    check-cast p2, Llyiahf/vczjk/zf1;

    const p1, 0x2f06228f

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p1, p0, Llyiahf/vczjk/qoa;->$insets:Llyiahf/vczjk/kna;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p1

    iget-object p3, p0, Llyiahf/vczjk/qoa;->$insets:Llyiahf/vczjk/kna;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    if-nez p1, :cond_0

    sget-object p1, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v0, p1, :cond_1

    :cond_0
    new-instance v0, Llyiahf/vczjk/y8a;

    invoke-direct {v0, p3}, Llyiahf/vczjk/y8a;-><init>(Llyiahf/vczjk/kna;)V

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1
    check-cast v0, Llyiahf/vczjk/y8a;

    const/4 p1, 0x0

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-object v0
.end method
