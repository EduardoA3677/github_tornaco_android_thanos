.class public final Llyiahf/vczjk/y68;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $contentWindowInsets:Llyiahf/vczjk/kna;

.field final synthetic $safeInsets:Llyiahf/vczjk/zs5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/zs5;Llyiahf/vczjk/kna;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/y68;->$safeInsets:Llyiahf/vczjk/zs5;

    iput-object p2, p0, Llyiahf/vczjk/y68;->$contentWindowInsets:Llyiahf/vczjk/kna;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/kna;

    iget-object v0, p0, Llyiahf/vczjk/y68;->$safeInsets:Llyiahf/vczjk/zs5;

    iget-object v1, p0, Llyiahf/vczjk/y68;->$contentWindowInsets:Llyiahf/vczjk/kna;

    new-instance v2, Llyiahf/vczjk/bs2;

    invoke-direct {v2, v1, p1}, Llyiahf/vczjk/bs2;-><init>(Llyiahf/vczjk/kna;Llyiahf/vczjk/kna;)V

    iget-object p1, v0, Llyiahf/vczjk/zs5;->OooO00o:Llyiahf/vczjk/qs5;

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1, v2}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
