.class public final Llyiahf/vczjk/eh;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $this_run:Llyiahf/vczjk/nh;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/nga;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/eh;->$this_run:Llyiahf/vczjk/nh;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/tg6;

    instance-of v0, p1, Llyiahf/vczjk/xa;

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/xa;

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    if-eqz p1, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/eh;->$this_run:Llyiahf/vczjk/nh;

    new-instance v1, Llyiahf/vczjk/oa;

    invoke-direct {v1, p1, v0}, Llyiahf/vczjk/oa;-><init>(Llyiahf/vczjk/xa;Llyiahf/vczjk/nh;)V

    iget-object p1, p1, Llyiahf/vczjk/xa;->o000000:Llyiahf/vczjk/as5;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/c76;->OooO0OO(Ljava/lang/Object;)I

    move-result v0

    if-ltz v0, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {p1, v1}, Llyiahf/vczjk/as5;->OooO0oO(Ljava/lang/Object;)V

    :cond_2
    :goto_1
    iget-object p1, p0, Llyiahf/vczjk/eh;->$this_run:Llyiahf/vczjk/nh;

    invoke-virtual {p1}, Landroid/view/ViewGroup;->removeAllViewsInLayout()V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
