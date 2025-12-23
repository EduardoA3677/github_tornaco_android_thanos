.class public final Llyiahf/vczjk/li2;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/d9;

.field public OooO0O0:Llyiahf/vczjk/f62;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ni2;Llyiahf/vczjk/oe3;)V
    .locals 6

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    sget-object v4, Llyiahf/vczjk/xh2;->OooO0Oo:Llyiahf/vczjk/h1a;

    new-instance v0, Llyiahf/vczjk/d9;

    new-instance v2, Llyiahf/vczjk/hi2;

    invoke-direct {v2, p0}, Llyiahf/vczjk/hi2;-><init>(Llyiahf/vczjk/li2;)V

    new-instance v3, Llyiahf/vczjk/ii2;

    invoke-direct {v3, p0}, Llyiahf/vczjk/ii2;-><init>(Llyiahf/vczjk/li2;)V

    move-object v1, p1

    move-object v5, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/d9;-><init>(Llyiahf/vczjk/ni2;Llyiahf/vczjk/hi2;Llyiahf/vczjk/ii2;Llyiahf/vczjk/h1a;Llyiahf/vczjk/oe3;)V

    iput-object v0, p0, Llyiahf/vczjk/li2;->OooO00o:Llyiahf/vczjk/d9;

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/li2;)Llyiahf/vczjk/f62;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/li2;->OooO0O0:Llyiahf/vczjk/f62;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "The density on DrawerState ("

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p0, ") was not set. Did you use DrawerState with the Drawer composable?"

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method
