.class public final Llyiahf/vczjk/al9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $manager:Llyiahf/vczjk/mk9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/mk9;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/al9;->$manager:Llyiahf/vczjk/mk9;

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

    const p3, 0x760d4197

    invoke-virtual {p2, p3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object p3, Llyiahf/vczjk/ch1;->OooO0oo:Llyiahf/vczjk/l39;

    invoke-virtual {p2, p3}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object p3

    check-cast p3, Llyiahf/vczjk/f62;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v0, v1, :cond_0

    new-instance v0, Llyiahf/vczjk/b24;

    const-wide/16 v2, 0x0

    invoke-direct {v0, v2, v3}, Llyiahf/vczjk/b24;-><init>(J)V

    invoke-static {v0}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v0

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_0
    check-cast v0, Llyiahf/vczjk/qs5;

    iget-object v2, p0, Llyiahf/vczjk/al9;->$manager:Llyiahf/vczjk/mk9;

    invoke-virtual {p2, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    iget-object v3, p0, Llyiahf/vczjk/al9;->$manager:Llyiahf/vczjk/mk9;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v2, :cond_1

    if-ne v4, v1, :cond_2

    :cond_1
    new-instance v4, Llyiahf/vczjk/wk9;

    invoke-direct {v4, v3, v0}, Llyiahf/vczjk/wk9;-><init>(Llyiahf/vczjk/mk9;Llyiahf/vczjk/qs5;)V

    invoke-virtual {p2, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_2
    check-cast v4, Llyiahf/vczjk/le3;

    invoke-virtual {p2, p3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v2, :cond_3

    if-ne v3, v1, :cond_4

    :cond_3
    new-instance v3, Llyiahf/vczjk/zk9;

    invoke-direct {v3, p3, v0}, Llyiahf/vczjk/zk9;-><init>(Llyiahf/vczjk/f62;Llyiahf/vczjk/qs5;)V

    invoke-virtual {p2, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_4
    check-cast v3, Llyiahf/vczjk/oe3;

    sget-object p3, Llyiahf/vczjk/ge8;->OooO00o:Llyiahf/vczjk/am;

    new-instance p3, Llyiahf/vczjk/ce8;

    invoke-direct {p3, v4, v3}, Llyiahf/vczjk/ce8;-><init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/oe3;)V

    invoke-static {p1, p3}, Llyiahf/vczjk/ng0;->OooOOoo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;)Llyiahf/vczjk/kl5;

    move-result-object p1

    const/4 p3, 0x0

    invoke-virtual {p2, p3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-object p1
.end method
