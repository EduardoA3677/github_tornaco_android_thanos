.class public final Llyiahf/vczjk/jh2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $drawerState:Llyiahf/vczjk/li2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/li2;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/jh2;->$drawerState:Llyiahf/vczjk/li2;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    check-cast p1, Llyiahf/vczjk/f62;

    iget-object p1, p0, Llyiahf/vczjk/jh2;->$drawerState:Llyiahf/vczjk/li2;

    iget-object p1, p1, Llyiahf/vczjk/li2;->OooO00o:Llyiahf/vczjk/d9;

    invoke-virtual {p1}, Llyiahf/vczjk/d9;->OooO0o()F

    move-result p1

    invoke-static {p1}, Llyiahf/vczjk/ye5;->Oooo000(F)I

    move-result p1

    int-to-long v0, p1

    const/16 p1, 0x20

    shl-long/2addr v0, p1

    const/4 p1, 0x0

    int-to-long v2, p1

    const-wide v4, 0xffffffffL

    and-long/2addr v2, v4

    or-long/2addr v0, v2

    new-instance p1, Llyiahf/vczjk/u14;

    invoke-direct {p1, v0, v1}, Llyiahf/vczjk/u14;-><init>(J)V

    return-object p1
.end method
