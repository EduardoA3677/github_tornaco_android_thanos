.class public final Llyiahf/vczjk/mx3;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $indication:Llyiahf/vczjk/lx3;

.field final synthetic $interactionSource:Llyiahf/vczjk/n24;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/lx3;Llyiahf/vczjk/n24;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/mx3;->$indication:Llyiahf/vczjk/lx3;

    iput-object p2, p0, Llyiahf/vczjk/mx3;->$interactionSource:Llyiahf/vczjk/n24;

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

    const p1, -0x15193045

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p1, p0, Llyiahf/vczjk/mx3;->$indication:Llyiahf/vczjk/lx3;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const p1, 0x4af582f5    # 8044922.5f

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    const/4 p1, 0x0

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object p3, Llyiahf/vczjk/ws7;->OooOOo:Llyiahf/vczjk/ws7;

    invoke-virtual {p2, p3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p3

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    if-nez p3, :cond_0

    sget-object p3, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v0, p3, :cond_1

    :cond_0
    new-instance v0, Llyiahf/vczjk/nx3;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1
    check-cast v0, Llyiahf/vczjk/nx3;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-object v0
.end method
